package pl.seniorshield.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/** User-facing alarms, e.g. "protection stopped working". */
object Alerts {
    const val CHANNEL_ID = "shield_alerts"
    const val PROTECTION_DOWN_ID = 2

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.alert_channel_name),
                    NotificationManager.IMPORTANCE_HIGH
                )
            )
        }
    }

    fun notifyProtectionDown(context: Context) {
        ensureChannel(context)
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(context.getString(R.string.alert_down_title))
            .setContentText(context.getString(R.string.alert_down_text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(PROTECTION_DOWN_ID, notification)
        } catch (e: SecurityException) {
            // notifications denied by the user
        }
    }

    fun cancelProtectionDown(context: Context) {
        NotificationManagerCompat.from(context).cancel(PROTECTION_DOWN_ID)
    }
}
