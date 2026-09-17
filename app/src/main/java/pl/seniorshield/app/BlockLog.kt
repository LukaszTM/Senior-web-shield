package pl.seniorshield.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Remembers which domains were blocked, how often and when, so the user can
 * review them. Kept in memory and persisted to a small JSON file in app storage.
 */
object BlockLog {

    class Entry(
        val domain: String,
        val category: Category,
        var count: Int,
        var lastSeen: Long,
    )

    private const val FILE_NAME = "blocked_log.json"
    private const val MAX_ENTRIES = 300
    private const val SAVE_DELAY_SECONDS = 2L

    private val lock = Any()
    private val entries = HashMap<String, Entry>()
    private var file: File? = null
    private val dirty = AtomicBoolean(false)
    private val saver = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "blocklog-saver").apply { isDaemon = true }
    }

    /** Bumped on every change so the UI can cheaply detect updates. */
    @Volatile
    var version: Long = 0
        private set

    fun init(context: Context) {
        synchronized(lock) {
            if (file != null) return
            val f = File(context.applicationContext.filesDir, FILE_NAME)
            file = f
            load(f)
        }
    }

    fun record(domain: String, category: Category) {
        synchronized(lock) {
            if (file == null) return
            val now = System.currentTimeMillis()
            val existing = entries[domain]
            if (existing != null) {
                existing.count++
                existing.lastSeen = now
            } else {
                if (entries.size >= MAX_ENTRIES) evictOldest()
                entries[domain] = Entry(domain, category, 1, now)
            }
            version++
        }
        scheduleSave()
    }

    /** Entries ordered from most recently blocked. */
    fun snapshot(): List<Entry> = synchronized(lock) {
        entries.values
            .map { Entry(it.domain, it.category, it.count, it.lastSeen) }
            .sortedByDescending { it.lastSeen }
    }

    fun clear() {
        synchronized(lock) {
            entries.clear()
            version++
        }
        scheduleSave()
    }

    /** Writes pending changes immediately (call when the service stops). */
    fun flush() {
        if (dirty.getAndSet(false)) save()
    }

    private fun evictOldest() {
        val oldest = entries.values.minByOrNull { it.lastSeen } ?: return
        entries.remove(oldest.domain)
    }

    private fun scheduleSave() {
        if (dirty.compareAndSet(false, true)) {
            saver.schedule({
                if (dirty.getAndSet(false)) save()
            }, SAVE_DELAY_SECONDS, TimeUnit.SECONDS)
        }
    }

    private fun save() {
        val f: File
        val json: String
        synchronized(lock) {
            f = file ?: return
            val arr = JSONArray()
            for (e in entries.values) {
                arr.put(
                    JSONObject()
                        .put("d", e.domain)
                        .put("c", e.category.key)
                        .put("n", e.count)
                        .put("t", e.lastSeen)
                )
            }
            json = arr.toString()
        }
        try {
            val tmp = File(f.parentFile, "$FILE_NAME.tmp")
            tmp.writeText(json)
            if (!tmp.renameTo(f)) f.writeText(json)
        } catch (e: Exception) {
            // Losing the history is acceptable; blocking must never fail because of it.
        }
    }

    private fun load(f: File) {
        if (!f.exists()) return
        try {
            val arr = JSONArray(f.readText())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val domain = o.optString("d")
                val category = Category.fromKey(o.optString("c")) ?: continue
                if (domain.isEmpty()) continue
                entries[domain] = Entry(domain, category, o.optInt("n", 1), o.optLong("t", 0L))
            }
        } catch (e: Exception) {
            entries.clear()
        }
    }
}
