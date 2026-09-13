package pl.seniorshield.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat

/**
 * Restores protection after the phone restarts, so a senior never has to
 * remember to re-enable it. Requires that VPN consent is still granted.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Prefs.isEnabled(context)) return
        if (VpnService.prepare(context) != null) return // consent lost; user must reopen the app
        val serviceIntent = Intent(context, ShieldVpnService::class.java)
            .setAction(ShieldVpnService.ACTION_START)
        ContextCompat.startForegroundService(context, serviceIntent)
    }
}
