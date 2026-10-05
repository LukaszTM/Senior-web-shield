package pl.seniorshield.app

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Prefs {
    private const val FILE = "shield_prefs"
    private const val KEY_ENABLED = "protection_enabled"
    private const val KEY_COUNT_DATE = "blocked_date"
    private const val KEY_COUNT_TODAY = "blocked_today"
    private const val KEY_COUNT_TOTAL = "blocked_total"
    private const val KEY_LISTS_UPDATED_AT = "lists_updated_at"
    private const val KEY_LISTS_COUNT = "lists_domain_count"
    private const val KEY_PAUSED_UNTIL = "paused_until"
    private const val KEY_PIN_HASH = "pin_hash"
    private const val KEY_PIN_SALT = "pin_salt"

    fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun isEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    private fun today(): String =
        SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())

    @Synchronized
    fun incrementBlocked(context: Context) {
        val p = prefs(context)
        val today = today()
        val sameDay = p.getString(KEY_COUNT_DATE, null) == today
        p.edit()
            .putString(KEY_COUNT_DATE, today)
            .putInt(KEY_COUNT_TODAY, if (sameDay) p.getInt(KEY_COUNT_TODAY, 0) + 1 else 1)
            .putInt(KEY_COUNT_TOTAL, p.getInt(KEY_COUNT_TOTAL, 0) + 1)
            .apply()
    }

    fun blockedToday(context: Context): Int {
        val p = prefs(context)
        return if (p.getString(KEY_COUNT_DATE, null) == today()) p.getInt(KEY_COUNT_TODAY, 0) else 0
    }

    fun blockedTotal(context: Context): Int =
        prefs(context).getInt(KEY_COUNT_TOTAL, 0)

    fun listsUpdatedAt(context: Context): Long =
        prefs(context).getLong(KEY_LISTS_UPDATED_AT, 0L)

    fun setListsUpdatedAt(context: Context, millis: Long) {
        prefs(context).edit().putLong(KEY_LISTS_UPDATED_AT, millis).apply()
    }

    fun listsDomainCount(context: Context): Int =
        prefs(context).getInt(KEY_LISTS_COUNT, 0)

    fun setListsDomainCount(context: Context, count: Int) {
        prefs(context).edit().putInt(KEY_LISTS_COUNT, count).apply()
    }

    /** When protection is paused: the time it resumes (ms), or 0 when not paused. */
    fun pausedUntil(context: Context): Long {
        val until = prefs(context).getLong(KEY_PAUSED_UNTIL, 0L)
        return if (until > System.currentTimeMillis()) until else 0L
    }

    fun setPausedUntil(context: Context, millis: Long) {
        prefs(context).edit().putLong(KEY_PAUSED_UNTIL, millis).apply()
    }

    fun hasPin(context: Context): Boolean = prefs(context).contains(KEY_PIN_HASH)

    fun setPin(context: Context, pin: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val saltText = Base64.encodeToString(salt, Base64.NO_WRAP)
        prefs(context).edit()
            .putString(KEY_PIN_SALT, saltText)
            .putString(KEY_PIN_HASH, hashPin(saltText, pin))
            .apply()
    }

    fun clearPin(context: Context) {
        prefs(context).edit().remove(KEY_PIN_HASH).remove(KEY_PIN_SALT).apply()
    }

    fun verifyPin(context: Context, pin: String): Boolean {
        val p = prefs(context)
        val salt = p.getString(KEY_PIN_SALT, null) ?: return false
        val expected = p.getString(KEY_PIN_HASH, null) ?: return false
        return MessageDigest.isEqual(hashPin(salt, pin).toByteArray(), expected.toByteArray())
    }

    private fun hashPin(salt: String, pin: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(salt.toByteArray())
        digest.update(pin.toByteArray())
        return Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
    }
}
