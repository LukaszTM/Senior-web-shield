package pl.seniorshield.app

import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView

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
            meta.text = context.getString(
                R.string.blocked_meta, times, TimeFormat.relative(context, entry.lastSeen)
            )
        }
    }
}
