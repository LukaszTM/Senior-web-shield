package pl.seniorshield.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton

class MainActivity : AppCompatActivity() {

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
                Toast.makeText(this, R.string.consent_needed, Toast.LENGTH_LONG).show()
                refreshUi()
            }
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* optional */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.status_text)
        statusHint = findViewById(R.id.status_hint)
        toggleButton = findViewById(R.id.toggle_button)
        counterText = findViewById(R.id.counter_text)

        toggleButton.setOnClickListener {
            if (ShieldVpnService.isRunning.get()) {
                stopProtection()
            } else {
                enableProtection()
            }
        }

        requestNotificationPermissionIfNeeded()
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
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            vpnConsentLauncher.launch(consentIntent)
        } else {
            startProtection()
        }
    }

    private fun startProtection() {
        Prefs.setEnabled(this, true)
        val intent = Intent(this, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
        refreshUi()
    }

    private fun stopProtection() {
        Prefs.setEnabled(this, false)
        val intent = Intent(this, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_STOP)
        startService(intent)
        refreshUi()
    }

    private fun refreshUi() {
        val running = ShieldVpnService.isRunning.get()
        if (running) {
            statusText.setText(R.string.status_on)
            statusText.setTextColor(ContextCompat.getColor(this, R.color.status_on))
            statusHint.setText(R.string.status_on_hint)
            toggleButton.setText(R.string.btn_disable)
            toggleButton.setBackgroundColor(ContextCompat.getColor(this, R.color.button_off))
        } else {
            statusText.setText(R.string.status_off)
            statusText.setTextColor(ContextCompat.getColor(this, R.color.status_off))
            statusHint.setText(R.string.status_off_hint)
            toggleButton.setText(R.string.btn_enable)
            toggleButton.setBackgroundColor(ContextCompat.getColor(this, R.color.button_on))
        }
        counterText.text = getString(
            R.string.blocked_counter,
            Prefs.blockedToday(this),
            Prefs.blockedTotal(this)
        )
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
