package com.example.tgunlocker

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.example.tgunlocker.network.WsTunnelEngine
import com.example.tgunlocker.service.ProxyForegroundService
import com.google.android.material.button.MaterialButton
import com.google.android.material.color.MaterialColors
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatusTitle: TextView
    private lateinit var tvStatusSub: TextView
    private lateinit var statusIndicator: android.view.View
    private lateinit var btnToggleProxy: MaterialButton
    private lateinit var btnSetupTelegram: MaterialButton
    private lateinit var switchAutostart: MaterialSwitch
    private lateinit var btnBatteryWhitelist: MaterialButton
    private lateinit var etCustomCdn: TextInputEditText
    private lateinit var etLocalPort: TextInputEditText
    private lateinit var tvLogsContent: TextView
    private lateinit var logsScroll: ScrollView

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            triggerProxyServiceStart()
        } else {
            Toast.makeText(this, "Notification permission is required for foreground service", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        getGithub()
        initViews()
        loadPreferences()
        setupListeners()
        observeLogs()
        observeServiceState()
    }

    override fun onPause() {
        super.onPause()
        savePreferences()
    }

    private fun getGithub() {
        findViewById<View>(R.id.btnGithub).setOnClickListener {
            val intent = Intent(
                Intent.ACTION_VIEW,
                Uri.parse("https://github.com/Qual1ty-dev/TgUnlocker")
            )
            startActivity(intent)
        }
    }

    private fun initViews() {
        tvStatusTitle = findViewById(R.id.tvStatusTitle)
        tvStatusSub = findViewById(R.id.tvStatusSub)
        statusIndicator = findViewById(R.id.statusIndicator)
        btnToggleProxy = findViewById(R.id.btnToggleProxy)
        btnSetupTelegram = findViewById(R.id.btnSetupTelegram)
        switchAutostart = findViewById(R.id.switchAutostart)
        btnBatteryWhitelist = findViewById(R.id.btnBatteryWhitelist)
        etCustomCdn = findViewById(R.id.etCustomCdn)
        etLocalPort = findViewById(R.id.etLocalPort)
        tvLogsContent = findViewById(R.id.tvLogsContent)
        logsScroll = findViewById(R.id.logsScroll)
    }

    private fun loadPreferences() {
        val prefs = getSharedPreferences("tgunlocker_prefs", Context.MODE_PRIVATE)
        switchAutostart.isChecked = prefs.getBoolean("pref_autostart", false)
        etCustomCdn.setText(prefs.getString("pref_cdn", ""))
        etLocalPort.setText(prefs.getInt("pref_port", 1080).toString())
    }

    private fun savePreferences() {
        val prefs = getSharedPreferences("tgunlocker_prefs", Context.MODE_PRIVATE)
        val port = etLocalPort.text.toString().toIntOrNull() ?: 1080
        val cdn = etCustomCdn.text.toString().trim()

        prefs.edit()
            .putBoolean("pref_autostart", switchAutostart.isChecked)
            .putInt("pref_port", port)
            .putString("pref_cdn", cdn.ifEmpty { null })
            .apply()
    }

    private fun setupListeners() {
        btnToggleProxy.setOnClickListener {
            savePreferences()
            if (ProxyForegroundService.isServiceRunning) {
                stopProxyService()
            } else {
                checkNotificationPermissionAndStart()
            }
        }

        btnSetupTelegram.setOnClickListener {
            savePreferences()
            val port = etLocalPort.text.toString().toIntOrNull() ?: 1080
            val secret = "dd${WsTunnelEngine.DEFAULT_SECRET}"
            val uri = Uri.parse("tg://proxy?server=127.0.0.1&port=$port&secret=$secret")
            val intent = Intent(Intent.ACTION_VIEW, uri).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            try {
                startActivity(intent)
            } catch (e: ActivityNotFoundException) {
                Toast.makeText(this, "Telegram app is not installed", Toast.LENGTH_SHORT).show()
            }
        }

        switchAutostart.setOnCheckedChangeListener { _, isChecked ->
            savePreferences()
            AppLogger.log("[CONF] Autostart set to $isChecked")
        }

        btnBatteryWhitelist.setOnClickListener {
            requestBatteryOptimizationExemption()
        }

        findViewById<TextView>(R.id.tvClearLogs).setOnClickListener {
            AppLogger.clear()
            tvLogsContent.text = ""
        }

        findViewById<TextView>(R.id.tvCopyLogs).setOnClickListener {
            val logs = tvLogsContent.text.toString()
            if (logs.isNotEmpty()) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("TgUnlocker Logs", logs)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Logs copied to clipboard", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkNotificationPermissionAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val permissionStatus = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            if (permissionStatus != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        triggerProxyServiceStart()
    }

    private fun triggerProxyServiceStart() {
        try {
            AppLogger.log("[UI] Requesting service start...")
            val serviceIntent = Intent(this, ProxyForegroundService::class.java).apply {
                action = ProxyForegroundService.ACTION_START
            }
            ContextCompat.startForegroundService(this, serviceIntent)
        } catch (e: Exception) {
            AppLogger.log("[FATAL] Service start failed: ${e.javaClass.simpleName} - ${e.message}")
        }
    }

    private fun stopProxyService() {
        val serviceIntent = Intent(this, ProxyForegroundService::class.java).apply {
            action = ProxyForegroundService.ACTION_STOP
        }
        ContextCompat.startForegroundService(this, serviceIntent)
    }

    private fun observeServiceState() {
        lifecycleScope.launch {
            ProxyForegroundService.isRunningFlow.collectLatest { isRunning ->
                updateUiState(isRunning)
            }
        }
    }

    private fun updateUiState(isRunning: Boolean) {
        val port = etLocalPort.text.toString().ifEmpty { "1080" }

        val indicatorDrawable = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(if (isRunning) Color.parseColor("#4CAF50") else Color.parseColor("#E53935"))
        }
        statusIndicator.background = indicatorDrawable

        val primaryColor = MaterialColors.getColor(btnToggleProxy, com.google.android.material.R.attr.colorPrimary)
        val onPrimaryColor = MaterialColors.getColor(btnToggleProxy, com.google.android.material.R.attr.colorOnPrimary)

        if (isRunning) {
            tvStatusTitle.text = getString(R.string.status_running)
            tvStatusSub.text = "Listening on 127.0.0.1:$port"
            btnToggleProxy.text = getString(R.string.btn_stop)
            btnToggleProxy.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#D32F2F"))
            btnToggleProxy.setTextColor(Color.WHITE)


            etCustomCdn.isEnabled = false
            etLocalPort.isEnabled = false
        } else {
            tvStatusTitle.text = getString(R.string.status_stopped)
            tvStatusSub.text = "127.0.0.1:$port"
            btnToggleProxy.text = getString(R.string.btn_start)
            btnToggleProxy.backgroundTintList = ColorStateList.valueOf(primaryColor)
            btnToggleProxy.setTextColor(onPrimaryColor)

            etCustomCdn.isEnabled = true
            etLocalPort.isEnabled = true

        }
    }

    private fun observeLogs() {
        AppLogger.setListener { fullLogs ->
            runOnUiThread {
                tvLogsContent.text = fullLogs
                logsScroll.post {
                    logsScroll.fullScroll(ScrollView.FOCUS_DOWN)
                }
            }
        }
    }

    override fun onDestroy() {
        AppLogger.setListener(null)
        super.onDestroy()
    }

    @SuppressLint("BatteryLife")
    private fun requestBatteryOptimizationExemption() {
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                try {
                    startActivity(intent)
                } catch (e: Exception) {
                    Toast.makeText(this, "Could not open settings", Toast.LENGTH_SHORT).show()
                }
            } else {
                Toast.makeText(this, "Already exempt from battery optimizations", Toast.LENGTH_SHORT).show()
            }
        }
    }
}