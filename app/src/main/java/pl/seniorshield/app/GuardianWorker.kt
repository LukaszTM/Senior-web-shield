package pl.seniorshield.app

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Periodically makes sure protection the user turned on is actually running.
 * Battery "optimisations" on some phones kill background services without a
 * trace; this tries to restart the service and, failing that, alerts the user.
 */
class GuardianWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        val context = applicationContext
        if (!shouldBeRunning(context)) return Result.success()

        try {
            ContextCompat.startForegroundService(
                context,
                Intent(context, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
            )
        } catch (e: Exception) {
            // background start refused (Android 12+); fall through to the alert
        }
        try {
            Thread.sleep(4000)
        } catch (e: InterruptedException) {
            return Result.success()
        }
        if (!ShieldVpnService.isRunning.get()) Alerts.notifyProtectionDown(context)
        return Result.success()
    }

    companion object {
        private const val WORK_NAME = "shield-guardian"

        fun shouldBeRunning(context: Context): Boolean =
            Prefs.isEnabled(context) &&
                Prefs.pausedUntil(context) == 0L &&
                !ShieldVpnService.isRunning.get()

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<GuardianWorker>(15, TimeUnit.MINUTES).build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
