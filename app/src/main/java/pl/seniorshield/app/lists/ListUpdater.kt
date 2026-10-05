package pl.seniorshield.app.lists

import android.content.Context
import android.util.Log
import pl.seniorshield.app.BlockList
import pl.seniorshield.app.Prefs
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.net.URL

/**
 * Downloads, stores and loads the external blocklists:
 * - the AdGuard DNS filter (ads and trackers, the same rules AdGuard's resolver applies),
 * - the CERT Polska warning list (domains used in fraud against Polish users).
 * Lists live in app storage and are refreshed about once a day while protection runs.
 */
class ListUpdater(private val context: Context) {

    companion object {
        private const val TAG = "ListUpdater"
        const val MAX_AGE_MS = 24L * 60 * 60 * 1000
        private const val MAX_BYTES = 20L * 1024 * 1024
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000

        private const val ADGUARD_FILE = "adguard.txt"
        private const val CERT_FILE = "cert.txt"
        private val ADGUARD_URLS = listOf(
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        )
        private val CERT_URLS = listOf(
            "https://hole.cert.pl/domains/v2/domains.txt",
            "https://hole.cert.pl/domains/domains.txt",
        )
        private const val MIN_ADGUARD_RULES = 1000
        private const val MIN_CERT_DOMAINS = 100
    }

    private val dir = File(context.filesDir, "lists")

    /** Builds the composite filter from the bundled list plus whatever is on disk. */
    fun loadFromDisk(builtin: BlockList): Filters {
        var phishing = DomainSet.EMPTY
        var ads = DomainSet.EMPTY
        var allowed = DomainSet.EMPTY
        File(dir, CERT_FILE).takeIf { it.isFile }?.let { f ->
            try {
                phishing = f.bufferedReader().use { ListParsers.parseDomainList(it) }
            } catch (e: Exception) {
                Log.w(TAG, "cannot read $CERT_FILE", e)
            }
        }
        File(dir, ADGUARD_FILE).takeIf { it.isFile }?.let { f ->
            try {
                val rules = f.bufferedReader().use { ListParsers.parseAdGuard(it) }
                ads = rules.blocked
                allowed = rules.allowed
            } catch (e: Exception) {
                Log.w(TAG, "cannot read $ADGUARD_FILE", e)
            }
        }
        return Filters(builtin, phishing, ads, allowed)
    }

    fun isStale(): Boolean =
        System.currentTimeMillis() - Prefs.listsUpdatedAt(context) > MAX_AGE_MS

    /**
     * Refreshes the lists when they are older than a day (or always with [force]).
     * Returns true when at least one list file changed. Network errors leave the
     * previous files untouched.
     */
    fun updateIfStale(force: Boolean): Boolean {
        if (!force && !isStale()) return false
        dir.mkdirs()
        var changed = false
        var allOk = true

        val adguard = fetchFirst(ADGUARD_URLS) { bytes ->
            ListParsers.parseAdGuard(bytes.reader()).blocked.size >= MIN_ADGUARD_RULES
        }
        if (adguard != null) changed = replace(ADGUARD_FILE, adguard) || changed else allOk = false

        val cert = fetchFirst(CERT_URLS) { bytes ->
            ListParsers.parseDomainList(bytes.reader()).size >= MIN_CERT_DOMAINS
        }
        if (cert != null) changed = replace(CERT_FILE, cert) || changed else allOk = false

        if (allOk) Prefs.setListsUpdatedAt(context, System.currentTimeMillis())
        return changed
    }

    private fun replace(name: String, content: ByteArray): Boolean {
        val target = File(dir, name)
        if (target.isFile && target.length() == content.size.toLong() &&
            target.readBytes().contentEquals(content)
        ) return false
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(content)
        if (!tmp.renameTo(target)) {
            target.writeBytes(content)
            tmp.delete()
        }
        return true
    }

    /** Downloads from the first URL whose content passes [valid]; null when none does. */
    private fun fetchFirst(urls: List<String>, valid: (ByteArray) -> Boolean): ByteArray? {
        for (url in urls) {
            try {
                val bytes = download(url)
                if (valid(bytes)) return bytes
                Log.w(TAG, "rejected implausible list from $url (${bytes.size} bytes)")
            } catch (e: Exception) {
                Log.w(TAG, "download failed: $url: $e")
            }
        }
        return null
    }

    private fun ByteArray.reader() = InputStreamReader(ByteArrayInputStream(this), Charsets.UTF_8)

    @Throws(IOException::class)
    private fun download(url: String): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.instanceFollowRedirects = true
            conn.setRequestProperty("User-Agent", "ShieldADV/1.2 (Android)")
            conn.setRequestProperty("Accept-Encoding", "identity")
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw IOException("HTTP $code")
            conn.inputStream.buffered().use { input ->
                val out = java.io.ByteArrayOutputStream(1 shl 20)
                val buf = ByteArray(16 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_BYTES) throw IOException("list too large")
                    out.write(buf, 0, n)
                }
                return out.toByteArray()
            }
        } finally {
            conn.disconnect()
        }
    }
}
