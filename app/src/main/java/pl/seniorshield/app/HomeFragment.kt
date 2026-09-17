package pl.seniorshield.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

/** The main "Protection" screen: one big on/off button and the blocked-ads counter. */
class HomeFragment : Fragment(R.layout.fragment_home) {

    private lateinit var statusText: TextView
    private lateinit var statusHint: TextView
    private lateinit var toggleButton: MaterialButton
    private lateinit var counterText: TextView

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

        toggleButton.setOnClickListener {
            if (ShieldVpnService.isRunning.get()) stopProtection() else enableProtection()
        }
    }

    override fun onResume() {
        super.onResume()
        uiHandler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        uiHandler.removeCallbacks(refreshRunnable)
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

    private fun stopProtection() {
        val context = requireContext()
        Prefs.setEnabled(context, false)
        val intent = Intent(context, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_STOP)
        context.startService(intent)
        refreshUi()
    }

    private fun refreshUi() {
        val context = context ?: return
        val running = ShieldVpnService.isRunning.get()
        if (running) {
            statusText.setText(R.string.status_on)
            statusText.setTextColor(ContextCompat.getColor(context, R.color.status_on))
            statusHint.setText(R.string.status_on_hint)
            toggleButton.setText(R.string.btn_disable)
            toggleButton.setBackgroundColor(ContextCompat.getColor(context, R.color.button_off))
        } else {
            statusText.setText(R.string.status_off)
            statusText.setTextColor(ContextCompat.getColor(context, R.color.status_off))
            statusHint.setText(R.string.status_off_hint)
            toggleButton.setText(R.string.btn_enable)
            toggleButton.setBackgroundColor(ContextCompat.getColor(context, R.color.button_on))
        }
        counterText.text = getString(
            R.string.blocked_counter,
            Prefs.blockedToday(context),
            Prefs.blockedTotal(context)
        )
    }
}
