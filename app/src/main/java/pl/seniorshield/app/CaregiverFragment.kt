package pl.seniorshield.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton

/** Settings meant for the caregiver: PIN and keeping the service alive. */
class CaregiverFragment : Fragment(R.layout.fragment_caregiver) {

    private lateinit var pinStatus: TextView
    private lateinit var pinSetButton: MaterialButton
    private lateinit var pinRemoveButton: MaterialButton
    private lateinit var batteryStatus: TextView
    private lateinit var batteryButton: MaterialButton

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        pinStatus = view.findViewById(R.id.pin_status)
        pinSetButton = view.findViewById(R.id.btn_pin_set)
        pinRemoveButton = view.findViewById(R.id.btn_pin_remove)
        batteryStatus = view.findViewById(R.id.battery_status)
        batteryButton = view.findViewById(R.id.btn_battery)
        view.findViewById<TextView>(R.id.version_text).text =
            getString(R.string.caregiver_version, BuildConfig.VERSION_NAME)

        pinSetButton.setOnClickListener {
            val context = requireContext()
            if (Prefs.hasPin(context)) {
                PinDialog.ask(context) { PinDialog.set(context) { refresh() } }
            } else {
                PinDialog.set(context) { refresh() }
            }
        }
        pinRemoveButton.setOnClickListener {
            val context = requireContext()
            PinDialog.ask(context) {
                Prefs.clearPin(context)
                Toast.makeText(context, R.string.pin_removed, Toast.LENGTH_LONG).show()
                refresh()
            }
        }
        batteryButton.setOnClickListener { requestBatteryExemption() }
        view.findViewById<MaterialButton>(R.id.btn_vpn_settings).setOnClickListener {
            try {
                startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
            } catch (e: Exception) {
                startActivity(Intent(Settings.ACTION_SETTINGS))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun requestBatteryExemption() {
        val context = requireContext()
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            .setData(Uri.parse("package:${context.packageName}"))
        try {
            startActivity(intent)
        } catch (e: Exception) {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
    }

    private fun refresh() {
        val context = context ?: return
        val hasPin = Prefs.hasPin(context)
        pinStatus.setText(if (hasPin) R.string.caregiver_pin_status_set else R.string.caregiver_pin_status_unset)
        pinSetButton.setText(if (hasPin) R.string.btn_pin_change else R.string.btn_pin_set)
        pinRemoveButton.visibility = if (hasPin) View.VISIBLE else View.GONE

        val pm = context.getSystemService(PowerManager::class.java)
        val exempt = pm.isIgnoringBatteryOptimizations(context.packageName)
        batteryStatus.setText(if (exempt) R.string.battery_ok else R.string.battery_not_ok)
        batteryButton.visibility = if (exempt) View.GONE else View.VISIBLE
    }
}
