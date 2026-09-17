package pl.seniorshield.app

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

/** The "Blocked" screen: every blocked site with its safety rating. */
class BlockedFragment : Fragment(R.layout.fragment_blocked) {

    private lateinit var summary: TextView
    private lateinit var empty: TextView
    private lateinit var list: RecyclerView
    private val adapter = BlockedAdapter()

    private var shownVersion = -1L
    private val uiHandler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshIfChanged()
            uiHandler.postDelayed(this, 2000)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        summary = view.findViewById(R.id.blocked_summary)
        empty = view.findViewById(R.id.blocked_empty)
        list = view.findViewById(R.id.blocked_list)
        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter
        BlockLog.init(requireContext())
    }

    override fun onResume() {
        super.onResume()
        shownVersion = -1
        uiHandler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        uiHandler.removeCallbacks(refreshRunnable)
    }

    private fun refreshIfChanged() {
        val version = BlockLog.version
        if (version == shownVersion) return
        shownVersion = version
        val entries = BlockLog.snapshot()
        adapter.submit(entries)
        summary.text = getString(R.string.blocked_summary, entries.size)
        empty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
        list.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
    }
}
