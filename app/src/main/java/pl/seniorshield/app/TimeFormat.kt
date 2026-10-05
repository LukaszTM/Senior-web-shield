package pl.seniorshield.app

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

object TimeFormat {
    /** "14:32" */
    fun clock(millis: Long): String =
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(millis))

    /** "dzisiaj o 14:32" for today, otherwise "5 paź, 14:32". */
    fun relative(context: Context, millis: Long): String {
        val date = Date(millis)
        val now = Calendar.getInstance()
        val then = Calendar.getInstance().apply { time = date }
        val sameDay = now.get(Calendar.YEAR) == then.get(Calendar.YEAR) &&
            now.get(Calendar.DAY_OF_YEAR) == then.get(Calendar.DAY_OF_YEAR)
        val clock = SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
        return if (sameDay) {
            context.getString(R.string.time_today, clock)
        } else {
            SimpleDateFormat("d MMM", Locale.getDefault()).format(date) + ", " + clock
        }
    }
}
