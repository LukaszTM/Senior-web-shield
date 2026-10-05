package pl.seniorshield.app

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import pl.seniorshield.app.dns.Dns
import pl.seniorshield.app.dns.DnsCache
import pl.seniorshield.app.dns.Packets
import pl.seniorshield.app.dns.UpstreamResolver
import pl.seniorshield.app.lists.Filters
import pl.seniorshield.app.lists.ListUpdater
import pl.seniorshield.app.net.UnderlyingNetworkWatcher
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A local, on-device VPN that captures only DNS traffic. Queries for domains on
 * the blocklists (bundled, CERT Polska, AdGuard DNS filter) get an immediate
 * NXDOMAIN answer; everything else is answered from a local cache or forwarded
 * to the operator's own resolver (AdGuard DNS only as a fallback), so CDN
 * selection and speed match a phone without the shield. No other traffic is
 * routed through the tunnel and nothing leaves the device except plain DNS.
 *
 * Protection can be paused for a while: the tunnel closes but the service stays
 * in the foreground and brings it back by itself when the pause ends.
 */
class ShieldVpnService : VpnService() {

    companion object {
        const val ACTION_START = "pl.seniorshield.app.action.START"
        const val ACTION_STOP = "pl.seniorshield.app.action.STOP"
        const val ACTION_PAUSE = "pl.seniorshield.app.action.PAUSE"
        const val ACTION_RESUME = "pl.seniorshield.app.action.RESUME"
        const val ACTION_UPDATE_LISTS = "pl.seniorshield.app.action.UPDATE_LISTS"
        const val EXTRA_PAUSE_MINUTES = "minutes"
        const val DEFAULT_PAUSE_MINUTES = 15

        val isRunning = AtomicBoolean(false)

        private const val TAG = "ShieldVpn"
        private const val TUN_ADDR_V4 = "10.111.222.1"
        private const val FAKE_DNS_V4 = "10.111.222.53"
        private const val TUN_ADDR_V6 = "fd00:6ea5:d15c::1"
        private const val FAKE_DNS_V6 = "fd00:6ea5:d15c::53"
        private const val CHANNEL_ID = "shield_status"
        private const val NOTIFICATION_ID = 1
        private const val DNS_PORT = 53
        private const val LIST_CHECK_INTERVAL_HOURS = 6L
        private const val LIST_RETRY_MINUTES = 15L
        private const val RESUME_ALARM_SLACK_MS = 5_000L
    }

    private var tun: ParcelFileDescriptor? = null
    private var tunOutput: FileOutputStream? = null
    private var workerThread: Thread? = null
    private var resolver: UpstreamResolver? = null
    private var networkWatcher: UnderlyingNetworkWatcher? = null
    private var blockList: BlockList? = null
    @Volatile private var filters: Filters? = null
    private val cache = DnsCache()
    private val listUpdater by lazy { ListUpdater(this) }
    private var maintenance: ScheduledExecutorService? = null
    private val listRetryPending = AtomicBoolean(false)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val resumeRunnable = Runnable { resumeFromPause() }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                clearPause()
                stopTunnel()
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_PAUSE -> pause(intent.getIntExtra(EXTRA_PAUSE_MINUTES, DEFAULT_PAUSE_MINUTES))
            ACTION_RESUME -> resumeFromPause()
            ACTION_UPDATE_LISTS -> {
                if (tun == null && Prefs.pausedUntil(this) == 0L) startVpn()
                maintenance?.execute { refreshLists(force = true) }
            }
            else -> {
                // ACTION_START, or a sticky restart after the system killed us (null intent).
                val pausedUntil = Prefs.pausedUntil(this)
                if (intent == null && pausedUntil > 0L) {
                    showPaused(pausedUntil)
                    armResume(pausedUntil)
                } else {
                    clearPause()
                    startVpn()
                }
            }
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (tun != null) return
        if (prepare(this) != null) {
            // Consent was revoked; the user must re-enable from the app.
            stopSelf()
            return
        }

        showRunning()

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(TUN_ADDR_V4, 24)
            .addRoute(FAKE_DNS_V4, 32)
            .addDnsServer(FAKE_DNS_V4)
        try {
            builder.addAddress(TUN_ADDR_V6, 64)
            builder.addRoute(FAKE_DNS_V6, 128)
            builder.addDnsServer(FAKE_DNS_V6)
        } catch (e: Exception) {
            Log.w(TAG, "IPv6 not available on this device: $e")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // A VPN counts as a metered network unless told otherwise, which makes
            // the system and apps throttle downloads, video quality and background
            // sync as if the user were on a capped data plan.
            builder.setMetered(false)
        }

        val fd = builder.establish()
        if (fd == null) {
            Log.e(TAG, "establish() returned null")
            stopSelf()
            return
        }
        tun = fd
        tunOutput = FileOutputStream(fd.fileDescriptor)
        BlockLog.init(this)
        val builtin = blockList ?: BlockList.load(this).also {
            blockList = it
            Log.i(TAG, "Bundled blocklist: ${it.size} domains")
        }
        if (filters == null) {
            filters = Filters(builtin)
            Prefs.setListsDomainCount(this, builtin.size)
        }

        val upstream = UpstreamResolver(this, ::onUpstreamAnswer)
        try {
            upstream.start()
        } catch (e: IOException) {
            Log.e(TAG, "cannot open upstream socket", e)
            stopTunnel()
            stopSelf()
            return
        }
        resolver = upstream
        networkWatcher = UnderlyingNetworkWatcher(this) { network, dns ->
            upstream.setUnderlyingNetwork(network, dns)
        }.also { it.start() }
        isRunning.set(true)
        Alerts.cancelProtectionDown(this)
        GuardianWorker.schedule(this)

        workerThread = Thread({ runLoop(fd) }, "shield-tun-reader").also { it.start() }

        // Load the downloaded lists off the main thread, then keep them fresh.
        val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "shield-maintenance").apply { isDaemon = true }
        }
        maintenance = scheduler
        scheduler.execute {
            applyFilters(listUpdater.loadFromDisk(builtin))
            refreshLists(force = false)
        }
        scheduler.scheduleWithFixedDelay(
            { refreshLists(force = false) },
            LIST_CHECK_INTERVAL_HOURS, LIST_CHECK_INTERVAL_HOURS, TimeUnit.HOURS
        )
    }

    // ---- pause / resume -------------------------------------------------

    private fun pause(minutes: Int) {
        val until = System.currentTimeMillis() + minutes.coerceAtLeast(1) * 60_000L
        stopTunnel()
        Prefs.setPausedUntil(this, until)
        showPaused(until)
        armResume(until)
        Log.i(TAG, "paused for $minutes min")
    }

    private fun resumeFromPause() {
        clearPause()
        startVpn()
    }

    /** Timer inside this (foreground) process, plus an alarm in case the process is killed meanwhile. */
    private fun armResume(until: Long) {
        mainHandler.removeCallbacks(resumeRunnable)
        mainHandler.postDelayed(resumeRunnable, (until - System.currentTimeMillis()).coerceAtLeast(0L))
        try {
            getSystemService(AlarmManager::class.java).setAndAllowWhileIdle(
                AlarmManager.RTC_WAKEUP, until + RESUME_ALARM_SLACK_MS, resumeIntent()
            )
        } catch (e: Exception) {
            Log.w(TAG, "resume alarm not set", e)
        }
    }

    private fun clearPause() {
        mainHandler.removeCallbacks(resumeRunnable)
        Prefs.setPausedUntil(this, 0L)
        try {
            getSystemService(AlarmManager::class.java).cancel(resumeIntent())
        } catch (e: Exception) {
            // nothing scheduled
        }
    }

    private fun resumeIntent(): PendingIntent = PendingIntent.getForegroundService(
        this, 1,
        Intent(this, ShieldVpnService::class.java).setAction(ACTION_RESUME),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    // ---- lists ------------------------------------------------------------

    /** Downloads newer lists when due and swaps them in; never blocks DNS handling. */
    private fun refreshLists(force: Boolean) {
        val builtin = blockList ?: return
        try {
            if (listUpdater.updateIfStale(force)) {
                applyFilters(listUpdater.loadFromDisk(builtin))
            } else if (force) {
                Prefs.setListsDomainCount(this, filters?.totalSize ?: builtin.size)
            }
        } catch (e: Exception) {
            Log.w(TAG, "list refresh failed", e)
        }
        // No network yet (e.g. right after boot)? Try again soon instead of in six hours.
        if (listUpdater.isStale() && listRetryPending.compareAndSet(false, true)) {
            maintenance?.schedule(Runnable {
                listRetryPending.set(false)
                refreshLists(force = false)
            }, LIST_RETRY_MINUTES, TimeUnit.MINUTES)
        }
    }

    private fun applyFilters(fresh: Filters) {
        filters = fresh
        cache.clear() // answers cached before the new lists arrived may now be blocked
        Prefs.setListsDomainCount(this, fresh.totalSize)
        Log.i(TAG, "filters: builtin=${fresh.builtinSize} cert=${fresh.phishingSize} adguard=${fresh.adsSize}")
    }

    // ---- packet handling ---------------------------------------------------

    private fun runLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!Thread.currentThread().isInterrupted) {
                val len = input.read(buffer)
                if (len <= 0) continue
                handlePacket(buffer.copyOf(len))
            }
        } catch (e: IOException) {
            // TUN closed — normal shutdown path.
        } catch (e: Exception) {
            Log.e(TAG, "reader loop failed", e)
        }
    }

    private fun handlePacket(packet: ByteArray) {
        // The only route through the tunnel is the fake DNS address, so any TCP
        // here is a DNS-over-TCP/TLS attempt (e.g. Android's Private DNS probe
        // on port 853). Refuse it at once so the client falls back immediately.
        Packets.parseTcp(packet)?.let { tcp ->
            if (!tcp.hasRst) writePacket(Packets.buildTcpReset(tcp))
            return
        }
        val udp = Packets.parseUdp(packet) ?: return
        if (udp.dstPort != DNS_PORT) return
        val question = Dns.parseQuestion(udp.payload)
        if (question == null) {
            resolver?.send(udp, null)
            return
        }

        filters?.lookup(question.name)?.let { category ->
            writePacket(Packets.buildUdpReply(udp, Dns.buildNxDomain(udp.payload, question)))
            onBlocked(question.name, category)
            return
        }

        cache.get(question.name, question.qtype)?.let { cached ->
            Dns.setId(cached, Dns.id(udp.payload))
            writePacket(Packets.buildUdpReply(udp, cached))
            if (Dns.isZeroAnswer(cached)) onBlocked(question.name, Category.FILTER)
            return
        }

        resolver?.send(udp, question)
    }

    private fun onUpstreamAnswer(query: UpstreamResolver.PendingQuery, answer: ByteArray) {
        writePacket(Packets.buildUdpReply(query.udp, answer))
        val question = query.question ?: return
        if (Dns.isZeroAnswer(answer)) onBlocked(question.name, Category.FILTER)
        DnsCache.cacheTtlFor(answer)?.let { ttl ->
            cache.put(question.name, question.qtype, answer, ttl)
        }
    }

    private fun onBlocked(domain: String, category: Category) {
        Prefs.incrementBlocked(this)
        BlockLog.record(domain, category)
    }

    private fun writePacket(packet: ByteArray) {
        val output = tunOutput ?: return
        try {
            synchronized(output) {
                output.write(packet)
            }
        } catch (e: IOException) {
            // TUN gone — the service is shutting down.
        }
    }

    // ---- lifecycle -----------------------------------------------------------

    /** Closes the tunnel and its helpers; the foreground notification is left to the caller. */
    private fun stopTunnel() {
        isRunning.set(false)
        maintenance?.shutdownNow()
        maintenance = null
        networkWatcher?.stop()
        networkWatcher = null
        resolver?.stop()
        resolver = null
        workerThread?.interrupt()
        try {
            tun?.close()
        } catch (e: IOException) {
            // ignore
        }
        tun = null
        tunOutput = null
        workerThread = null
        cache.clear()
        BlockLog.flush()
    }

    override fun onRevoke() {
        // Another VPN app took over or the user revoked consent in settings.
        Prefs.setEnabled(this, false)
        clearPause()
        stopTunnel()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Some phones kill the service when the app is swiped away; come back.
        if (tun == null && Prefs.isEnabled(this) && Prefs.pausedUntil(this) == 0L) startVpn()
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(resumeRunnable)
        stopTunnel()
        super.onDestroy()
    }

    // ---- notifications -------------------------------------------------------

    private fun showRunning() {
        startInForeground(
            buildNotification(
                getString(R.string.notification_title),
                getString(R.string.notification_text),
                action = null
            )
        )
    }

    private fun showPaused(until: Long) {
        val resume = NotificationCompat.Action.Builder(
            R.drawable.ic_shield, getString(R.string.notification_resume), resumeIntent()
        ).build()
        startInForeground(
            buildNotification(
                getString(R.string.notification_paused_title),
                getString(R.string.notification_paused_text, TimeFormat.clock(until)),
                action = resume
            )
        )
    }

    private fun buildNotification(title: String, text: String, action: NotificationCompat.Action?): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(contentIntent)
        if (action != null) builder.addAction(action)
        return builder.build()
    }

    private fun startInForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this, NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }
}
