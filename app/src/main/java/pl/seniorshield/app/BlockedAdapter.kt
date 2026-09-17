package pl.seniorshield.app

import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

class BlockedAdapter : RecyclerView.Adapter<BlockedAdapter.Holder>() {

    private var items: List<BlockLog.Entry> = emptyList()

    fun submit(entries: List<BlockLog.Entry>) {
        items = entries
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_blocked, parent, false)
        return Holder(view)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: Holder, position: Int) = holder.bind(items[position])

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        private val badge: TextView = view.findViewById(R.id.badge)
        private val domain: TextView = view.findViewById(R.id.domain)
        private val description: TextView = view.findViewById(R.id.description)
        private val meta: TextView = view.findViewById(R.id.meta)

        fun bind(entry: BlockLog.Entry) {
            val context = itemView.context
            val category = entry.category
            badge.setText(category.ratingRes)
            badge.backgroundTintList =
                ColorStateList.valueOf(ContextCompat.getColor(context, category.colorRes))
            domain.text = entry.domain
            description.text = context.getString(category.nameRes) + ": " +
                context.getString(category.descriptionRes)
            val times = context.resources.getQuantityString(
                R.plurals.blocked_times, entry.count, entry.count
            )
            meta.text = context.getString(R.string.blocked_meta, times, formatTime(entry.lastSeen))
        }

        private fun formatTime(millis: Long): String {
            val date = Date(millis)
            val now = Calendar.getInstance()
            val then = Calendar.getInstance().apply { time = date }
            val sameDay = now.get(Calendar.YEAR) == then.get(Calendar.YEAR) &&
                now.get(Calendar.DAY_OF_YEAR) == then.get(Calendar.DAY_OF_YEAR)
            val clock = SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
            return if (sameDay) {
                itemView.context.getString(R.string.time_today, clock)
            } else {
                SimpleDateFormat("d MMM", Locale.getDefault()).format(date) + ", " + clock
            }
        }
    }
}
