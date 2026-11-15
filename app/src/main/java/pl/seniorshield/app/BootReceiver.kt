package pl.seniorshield.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat

/**
 * Restores protection after the phone restarts or the app is updated, so a
 * senior never has to remember to re-enable it. Requires that VPN consent is
 * still granted; otherwise it alerts the user instead of failing silently.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
        private val ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            "android.intent.action.QUICKBOOT_POWERON",
            "com.htc.intent.action.QUICKBOOT_POWERON",
        )
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action !in ACTIONS) return
        GuardianWorker.schedule(context)
        if (!Prefs.isEnabled(context)) return
        if (Prefs.pausedUntil(context) > 0L) return
        if (ShieldVpnService.isRunning.get()) return

        if (VpnService.prepare(context) != null) {
            // Consent was lost (e.g. another VPN app was used): the user must tap.
            Alerts.notifyProtectionDown(context)
            return
        }
        try {
            ContextCompat.startForegroundService(
                context,
                Intent(context, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
            )
        } catch (e: Exception) {
            Log.w(TAG, "cannot start protection from ${intent.action}", e)
            Alerts.notifyProtectionDown(context)
        }
    }
}
