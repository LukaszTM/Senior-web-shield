package pl.seniorshield.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import pl.seniorshield.app.dns.Dns
import pl.seniorshield.app.dns.DnsCache
import pl.seniorshield.app.dns.Packets
import pl.seniorshield.app.dns.UpstreamResolver
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A local, on-device VPN that captures only DNS traffic. Queries for domains on
 * the blocklist get an immediate NXDOMAIN answer; everything else is answered
 * from a local cache or forwarded to an ad-blocking upstream resolver (AdGuard
 * DNS). No other traffic is routed through the tunnel and nothing leaves the
 * device except plain DNS queries.
 */
class ShieldVpnService : VpnService() {

    companion object {
        const val ACTION_START = "pl.seniorshield.app.action.START"
        const val ACTION_STOP = "pl.seniorshield.app.action.STOP"

        val isRunning = AtomicBoolean(false)

        private const val TAG = "ShieldVpn"
        private const val TUN_ADDR_V4 = "10.111.222.1"
        private const val FAKE_DNS_V4 = "10.111.222.53"
        private const val TUN_ADDR_V6 = "fd00:6ea5:d15c::1"
        private const val FAKE_DNS_V6 = "fd00:6ea5:d15c::53"
        private const val CHANNEL_ID = "shield_status"
        private const val NOTIFICATION_ID = 1
        private const val DNS_PORT = 53
    }

    private var tun: ParcelFileDescriptor? = null
    private var tunOutput: FileOutputStream? = null
    private var workerThread: Thread? = null
    private var resolver: UpstreamResolver? = null
    private var blockList: BlockList? = null
    private val cache = DnsCache()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
                START_NOT_STICKY
            }
            else -> {
                startVpn()
                START_STICKY
            }
        }
    }

    private fun startVpn() {
        if (tun != null) return
        if (prepare(this) != null) {
            // Consent was revoked; the user must re-enable from the app.
            stopSelf()
            return
        }

        startAsForeground()

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
        if (blockList == null) {
            blockList = BlockList.load(this)
            Log.i(TAG, "Blocklist loaded: ${blockList?.size} domains")
        }

        val upstream = UpstreamResolver(this, ::onUpstreamAnswer)
        try {
            upstream.start()
        } catch (e: IOException) {
            Log.e(TAG, "cannot open upstream socket", e)
            stopVpn()
            stopSelf()
            return
        }
        resolver = upstream
        isRunning.set(true)

        workerThread = Thread({ runLoop(fd) }, "shield-tun-reader").also { it.start() }
    }

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

        blockList?.lookup(question.name)?.let { category ->
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

    private fun stopVpn() {
        isRunning.set(false)
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
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        // Another VPN app took over or the user revoked consent in settings.
        Prefs.setEnabled(this, false)
        stopVpn()
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startAsForeground() {
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
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .build()
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
