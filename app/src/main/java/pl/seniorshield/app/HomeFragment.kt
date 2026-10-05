package pl.seniorshield.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

/** The main "Protection" screen: one big on/off button and the blocked-ads counter. */
class HomeFragment : Fragment(R.layout.fragment_home) {

    private lateinit var statusText: TextView
    private lateinit var statusHint: TextView
    private lateinit var toggleButton: MaterialButton
    private lateinit var counterText: TextView
    private lateinit var listsStatus: TextView
    private lateinit var downBanner: TextView

    private val uiHandler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshUi()
            uiHandler.postDelayed(this, 2000)
        }
    }

    private val vpnConsentLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startProtection()
            } else {
                Toast.makeText(requireContext(), R.string.consent_needed, Toast.LENGTH_LONG).show()
                refreshUi()
            }
        }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        statusText = view.findViewById(R.id.status_text)
        statusHint = view.findViewById(R.id.status_hint)
        toggleButton = view.findViewById(R.id.toggle_button)
        counterText = view.findViewById(R.id.counter_text)
        listsStatus = view.findViewById(R.id.lists_status)
        downBanner = view.findViewById(R.id.down_banner)

        toggleButton.setOnClickListener {
            when {
                ShieldVpnService.isRunning.get() -> showDisableDialog()
                Prefs.pausedUntil(requireContext()) > 0L -> sendAction(ShieldVpnService.ACTION_RESUME)
                else -> enableProtection()
            }
        }
        downBanner.setOnClickListener { enableProtection() }
        listsStatus.setOnClickListener { requestListUpdate() }
    }

    override fun onResume() {
        super.onResume()
        healIfNeeded()
        uiHandler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        uiHandler.removeCallbacks(refreshRunnable)
    }

    /** Protection was on but the service is gone (killed by the system): bring it back quietly. */
    private fun healIfNeeded() {
        val context = requireContext()
        if (!GuardianWorker.shouldBeRunning(context)) return
        if (VpnService.prepare(context) != null) return // consent lost; the banner asks for a tap
        startProtection()
        Toast.makeText(context, R.string.toast_healed, Toast.LENGTH_LONG).show()
    }

    private fun showDisableDialog() {
        val context = requireContext()
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_disable, null)
        val dialog = AlertDialog.Builder(context).setView(view).create()
        view.findViewById<MaterialButton>(R.id.btn_pause).setOnClickListener {
            dialog.dismiss()
            pauseProtection()
        }
        view.findViewById<MaterialButton>(R.id.btn_disable).setOnClickListener {
            dialog.dismiss()
            if (Prefs.hasPin(context)) PinDialog.ask(context) { stopProtection() } else stopProtection()
        }
        view.findViewById<MaterialButton>(R.id.btn_cancel).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun enableProtection() {
        val consentIntent = VpnService.prepare(requireContext())
        if (consentIntent != null) {
            vpnConsentLauncher.launch(consentIntent)
        } else {
            startProtection()
        }
    }

    private fun startProtection() {
        val context = requireContext()
        Prefs.setEnabled(context, true)
        val intent = Intent(context, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
        ContextCompat.startForegroundService(context, intent)
        refreshUi()
    }

    private fun pauseProtection() {
        val context = requireContext()
        val intent = Intent(context, ShieldVpnService::class.java)
            .setAction(ShieldVpnService.ACTION_PAUSE)
            .putExtra(ShieldVpnService.EXTRA_PAUSE_MINUTES, ShieldVpnService.DEFAULT_PAUSE_MINUTES)
        context.startService(intent)
        Toast.makeText(context, R.string.toast_paused, Toast.LENGTH_LONG).show()
        refreshUi()
    }

    private fun stopProtection() {
        val context = requireContext()
        Prefs.setEnabled(context, false)
        sendAction(ShieldVpnService.ACTION_STOP)
    }

    private fun sendAction(action: String) {
        val context = requireContext()
        context.startService(Intent(context, ShieldVpnService::class.java).setAction(action))
        refreshUi()
    }

    private fun requestListUpdate() {
        val context = requireContext()
        if (!ShieldVpnService.isRunning.get()) {
            Toast.makeText(context, R.string.lists_need_protection, Toast.LENGTH_SHORT).show()
            return
        }
        sendAction(ShieldVpnService.ACTION_UPDATE_LISTS)
        Toast.makeText(context, R.string.lists_updating, Toast.LENGTH_SHORT).show()
    }

    private fun refreshUi() {
        val context = context ?: return
        val running = ShieldVpnService.isRunning.get()
        val pausedUntil = Prefs.pausedUntil(context)
        when {
            running -> {
                statusText.setText(R.string.status_on)
                statusText.setTextColor(ContextCompat.getColor(context, R.color.status_on))
                statusHint.setText(R.string.status_on_hint)
                toggleButton.setText(R.string.btn_disable)
                toggleButton.setBackgroundColor(ContextCompat.getColor(context, R.color.button_off))
            }
            pausedUntil > 0L -> {
                statusText.setText(R.string.status_paused)
                statusText.setTextColor(ContextCompat.getColor(context, R.color.status_paused))
                statusHint.text = getString(R.string.status_paused_hint, TimeFormat.clock(pausedUntil))
                toggleButton.setText(R.string.btn_resume)
                toggleButton.setBackgroundColor(ContextCompat.getColor(context, R.color.button_on))
            }
            else -> {
                statusText.setText(R.string.status_off)
                statusText.setTextColor(ContextCompat.getColor(context, R.color.status_off))
                statusHint.setText(R.string.status_off_hint)
                toggleButton.setText(R.string.btn_enable)
                toggleButton.setBackgroundColor(ContextCompat.getColor(context, R.color.button_on))
            }
        }
        downBanner.visibility =
            if (GuardianWorker.shouldBeRunning(context)) View.VISIBLE else View.GONE

        counterText.text = getString(
            R.string.blocked_counter,
            Prefs.blockedToday(context),
            Prefs.blockedTotal(context)
        )
        val updatedAt = Prefs.listsUpdatedAt(context)
        val count = Prefs.listsDomainCount(context)
        listsStatus.text = if (updatedAt == 0L && count == 0) {
            getString(R.string.lists_status_initial)
        } else if (updatedAt == 0L) {
            getString(R.string.lists_status_pending, count)
        } else {
            getString(
                R.string.lists_status,
                java.text.NumberFormat.getIntegerInstance().format(count),
                TimeFormat.relative(context, updatedAt)
            )
        }
    }
}
