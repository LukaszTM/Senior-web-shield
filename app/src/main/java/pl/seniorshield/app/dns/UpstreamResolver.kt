package pl.seniorshield.app.dns

import android.net.VpnService
import android.util.Log
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Forwards DNS queries to the upstream resolvers over one shared, VPN-protected
 * UDP socket. Queries are tracked by a locally assigned transaction id, so any
 * number can be in flight at once and a slow answer never blocks the others.
 * A query that gets no answer quickly is re-sent to the next upstream; whichever
 * replies first wins.
 */
class UpstreamResolver(
    private val vpn: VpnService,
    private val onAnswer: (PendingQuery, ByteArray) -> Unit,
) {
    class PendingQuery(
        val id: Int,
        val originalId: Int,
        val udp: UdpDatagram,
        val question: DnsQuestion?,
        val payload: ByteArray,
        @Volatile var firstSentAt: Long,
        @Volatile var attempt: Int,
    )

    companion object {
        private const val TAG = "UpstreamResolver"
        private const val RETRY_AFTER_MS = 1000L
        private const val GIVE_UP_AFTER_MS = 5000L
        private const val SWEEP_INTERVAL_MS = 250L
        private const val DNS_PORT = 53

        // AdGuard DNS "Default" (ads, trackers, phishing) — IPv4 first, IPv6 as a
        // fallback for IPv6-only mobile networks. Literal addresses: no lookup.
        private val UPSTREAMS: List<InetAddress> = listOf(
            "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
        ).map { InetAddress.getByName(it) }
    }

    private val pending = ConcurrentHashMap<Int, PendingQuery>()
    private val nextId = AtomicInteger(1)
    @Volatile private var preferredUpstream = 0
    @Volatile private var socket: DatagramSocket? = null
    private var receiver: Thread? = null
    private var sweeper: ScheduledExecutorService? = null

    @Throws(IOException::class)
    fun start() {
        val s = DatagramSocket()
        if (!vpn.protect(s)) {
            s.close()
            throw IOException("protect() failed")
        }
        try {
            s.receiveBufferSize = 256 * 1024
        } catch (e: SocketException) {
            // best effort
        }
        socket = s
        receiver = Thread({ receiveLoop(s) }, "shield-dns-receiver").also { it.start() }
        sweeper = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "shield-dns-sweeper").apply { isDaemon = true }
        }.also {
            it.scheduleWithFixedDelay(::sweep, SWEEP_INTERVAL_MS, SWEEP_INTERVAL_MS, TimeUnit.MILLISECONDS)
        }
    }

    fun stop() {
        sweeper?.shutdownNow()
        sweeper = null
        socket?.close()
        socket = null
        receiver?.interrupt()
        receiver = null
        pending.clear()
    }

    /** Forwards [udp] (a DNS query) upstream; the answer arrives via [onAnswer]. */
    fun send(udp: UdpDatagram, question: DnsQuestion?) {
        if (udp.payload.size < 12) return
        val id = allocateId() ?: return
        val payload = udp.payload.copyOf()
        val originalId = Dns.id(payload)
        Dns.setId(payload, id)
        val query = PendingQuery(id, originalId, udp, question, payload, System.currentTimeMillis(), 0)
        pending[id] = query
        if (!transmit(query)) pending.remove(id)
    }

    val inFlight: Int get() = pending.size

    private fun allocateId(): Int? {
        repeat(0x10000) {
            val id = nextId.getAndUpdate { if (it >= 0xFFFF) 1 else it + 1 }
            if (!pending.containsKey(id)) return id
        }
        return null
    }

    /** Sends the query to the upstream for its current attempt; tries the others on a send error. */
    private fun transmit(query: PendingQuery): Boolean {
        val s = socket ?: return false
        val n = UPSTREAMS.size
        repeat(n) { offset ->
            val index = (preferredUpstream + query.attempt + offset) % n
            try {
                s.send(DatagramPacket(query.payload, query.payload.size, UPSTREAMS[index], DNS_PORT))
                return true
            } catch (e: IOException) {
                // e.g. network unreachable for this address family — try the next upstream
            }
        }
        return false
    }

    private fun receiveLoop(s: DatagramSocket) {
        val buf = ByteArray(4096)
        val packet = DatagramPacket(buf, buf.size)
        while (!Thread.currentThread().isInterrupted) {
            try {
                packet.setData(buf, 0, buf.size)
                s.receive(packet)
            } catch (e: IOException) {
                if (s.isClosed) return
                continue
            }
            if (packet.length < 12) continue
            val answer = buf.copyOf(packet.length)
            val query = pending.remove(Dns.id(answer)) ?: continue
            Dns.setId(answer, query.originalId)
            val from = packet.address
            val index = UPSTREAMS.indexOfFirst { it == from }
            if (index >= 0) preferredUpstream = index
            try {
                onAnswer(query, answer)
            } catch (e: Exception) {
                Log.w(TAG, "answer handler failed", e)
            }
        }
    }

    private fun sweep() {
        val now = System.currentTimeMillis()
        for (query in pending.values) {
            val age = now - query.firstSentAt
            when {
                age > GIVE_UP_AFTER_MS -> pending.remove(query.id)
                age > RETRY_AFTER_MS * (query.attempt + 1) && query.attempt < UPSTREAMS.size - 1 -> {
                    query.attempt++
                    transmit(query)
                }
            }
        }
    }
}
