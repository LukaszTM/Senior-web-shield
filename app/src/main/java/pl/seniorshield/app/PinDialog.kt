package pl.seniorshield.app

import android.content.Context
import android.text.InputType
import android.view.LayoutInflater
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog

/** Large-print PIN prompts for the caregiver PIN. */
object PinDialog {

    private const val MIN_LENGTH = 4
    private const val MAX_LENGTH = 6

    /** Asks for the existing PIN; runs [onSuccess] only when it matches. */
    fun ask(context: Context, onSuccess: () -> Unit) {
        prompt(context, context.getString(R.string.pin_title_enter)) { pin ->
            if (Prefs.verifyPin(context, pin)) {
                onSuccess()
            } else {
                Toast.makeText(context, R.string.pin_wrong, Toast.LENGTH_LONG).show()
            }
        }
    }

    /** Sets a new PIN (entered twice); runs [onDone] after it is saved. */
    fun set(context: Context, onDone: () -> Unit) {
        prompt(context, context.getString(R.string.pin_title_new)) { first ->
            if (first.length !in MIN_LENGTH..MAX_LENGTH) {
                Toast.makeText(context, R.string.pin_too_short, Toast.LENGTH_LONG).show()
                return@prompt
            }
            prompt(context, context.getString(R.string.pin_title_confirm)) { second ->
                if (first == second) {
                    Prefs.setPin(context, first)
                    Toast.makeText(context, R.string.pin_saved, Toast.LENGTH_LONG).show()
                    onDone()
                } else {
                    Toast.makeText(context, R.string.pin_mismatch, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun prompt(context: Context, title: String, onEntered: (String) -> Unit) {
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_pin, null)
        view.findViewById<TextView>(R.id.pin_title).text = title
        val input = view.findViewById<EditText>(R.id.pin_input)
        input.inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        val dialog = AlertDialog.Builder(context)
            .setView(view)
            .setPositiveButton(R.string.btn_ok) { _, _ -> onEntered(input.text.toString().trim()) }
            .setNegativeButton(R.string.btn_cancel, null)
            .create()
        dialog.show()
        input.requestFocus()
    }
}
