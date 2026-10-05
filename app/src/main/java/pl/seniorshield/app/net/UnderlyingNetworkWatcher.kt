package pl.seniorshield.app.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Tracks the best non-VPN network with internet access (the one Android would
 * use if our tunnel were not there) and reports its DNS servers. Forwarding
 * queries to the operator's own resolver keeps CDN server selection and
 * latency identical to a phone without the shield.
 */
class UnderlyingNetworkWatcher(
    context: Context,
    private val onChange: (Network?, List<InetAddress>) -> Unit,
) {
    companion object {
        private const val TAG = "UnderlyingNetwork"
    }

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    @Volatile private var current: Network? = null
    private var registered = false
    private var thread: HandlerThread? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            current = network
            publish(network, cm.getLinkProperties(network))
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (network == current) publish(network, linkProperties)
        }

        override fun onLost(network: Network) {
            if (network == current) {
                current = null
                onChange(null, emptyList())
            }
        }
    }

    fun start() {
        if (registered) return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            val t = HandlerThread("shield-network-watcher").also { it.start() }
            thread = t
            // Callbacks open sockets, so keep them off the main thread.
            cm.requestNetwork(request, callback, Handler(t.looper))
            registered = true
        } catch (e: Exception) {
            Log.w(TAG, "requestNetwork failed; staying on fallback resolvers", e)
        }
    }

    fun stop() {
        if (!registered) return
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            // already unregistered
        }
        registered = false
        current = null
        thread?.quitSafely()
        thread = null
    }

    private fun publish(network: Network, lp: LinkProperties?) {
        val servers = lp?.dnsServers.orEmpty()
            .filter { !it.isAnyLocalAddress && !it.isLoopbackAddress }
            // IPv4 first: reachable on every network, no scope-id pitfalls
            .sortedBy { if (it is Inet4Address) 0 else 1 }
        onChange(network, servers)
    }
}
