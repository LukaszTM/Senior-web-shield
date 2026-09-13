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
import pl.seniorshield.app.dns.Packets
import pl.seniorshield.app.dns.UdpDatagram
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A local, on-device VPN that captures only DNS traffic. Queries for domains on
 * the blocklist get an immediate NXDOMAIN answer; everything else is forwarded
 * to an ad-blocking upstream resolver (AdGuard DNS). No other traffic is routed
 * through the tunnel and nothing leaves the device except plain DNS queries.
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
        private const val DNS_TIMEOUT_MS = 5000
    }

    // AdGuard DNS "Default" servers: block ads, trackers and known scam/phishing
    // domains at the resolver level — a second protective layer on top of the
    // bundled blocklist.
    private val upstreams: List<InetAddress> by lazy {
        listOf(
            InetAddress.getByAddress(byteArrayOf(94.toByte(), 140.toByte(), 14, 14)),
            InetAddress.getByAddress(byteArrayOf(94.toByte(), 140.toByte(), 15, 15)),
        )
    }

    private var tun: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    private var blockList: BlockList? = null
    private val executor = ThreadPoolExecutor(
        2, 16, 30, TimeUnit.SECONDS, LinkedBlockingQueue(256),
        ThreadPoolExecutor.DiscardOldestPolicy()
    )

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

        val fd = builder.establish()
        if (fd == null) {
            Log.e(TAG, "establish() returned null")
            stopSelf()
            return
        }
        tun = fd
        if (blockList == null) {
            blockList = BlockList.load(this)
            Log.i(TAG, "Blocklist loaded: ${blockList?.size} domains")
        }
        isRunning.set(true)

        workerThread = Thread({ runLoop(fd) }, "shield-tun-reader").also { it.start() }
    }

    private fun runLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!Thread.currentThread().isInterrupted) {
                val len = input.read(buffer)
                if (len <= 0) continue
                val packet = buffer.copyOf(len)
                handlePacket(packet, output)
            }
        } catch (e: IOException) {
            // TUN closed — normal shutdown path.
        } catch (e: Exception) {
            Log.e(TAG, "reader loop failed", e)
        }
    }

    private fun handlePacket(packet: ByteArray, output: FileOutputStream) {
        val udp = Packets.parseUdp(packet) ?: return
        if (udp.dstPort != 53) return
        val question = Dns.parseQuestion(udp.payload)

        if (question != null && blockList?.isBlocked(question.name) == true) {
            val reply = Packets.buildUdpReply(udp, Dns.buildNxDomain(udp.payload, question))
            writePacket(output, reply)
            Prefs.incrementBlocked(this)
            return
        }
        executor.execute { forwardQuery(udp, output) }
    }

    private fun forwardQuery(udp: UdpDatagram, output: FileOutputStream) {
        for (upstream in upstreams) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                if (!protect(socket)) {
                    Log.w(TAG, "protect() failed")
                    return
                }
                socket.soTimeout = DNS_TIMEOUT_MS
                socket.send(DatagramPacket(udp.payload, udp.payload.size, upstream, 53))
                val buf = ByteArray(4096)
                val response = DatagramPacket(buf, buf.size)
                socket.receive(response)
                writePacket(output, Packets.buildUdpReply(udp, buf.copyOf(response.length)))
                return
            } catch (e: IOException) {
                // Timeout or network error — try the next upstream.
            } finally {
                socket?.close()
            }
        }
    }

    private fun writePacket(output: FileOutputStream, packet: ByteArray) {
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
        workerThread?.interrupt()
        try {
            tun?.close()
        } catch (e: IOException) {
            // ignore
        }
        tun = null
        workerThread = null
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
        executor.shutdownNow()
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
