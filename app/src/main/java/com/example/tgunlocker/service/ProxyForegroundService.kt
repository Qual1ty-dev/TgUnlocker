package com.example.tgunlocker.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.widget.Toast
import androidx.core.app.NotificationCompat
import com.example.tgunlocker.AppLogger
import com.example.tgunlocker.MainActivity
import com.example.tgunlocker.network.StickyBalancer
import com.example.tgunlocker.network.WsTunnelEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ProxyForegroundService : Service() {

    private var engine: WsTunnelEngine? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private lateinit var connectivityManager: ConnectivityManager
    private var isNetworkRegistered = false

    companion object {
        const val ACTION_START = "ACTION_START"
        const val ACTION_STOP = "ACTION_STOP"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "tgunlocker_service_silent_v1"

        private val _isRunningFlow = MutableStateFlow(false)
        val isRunningFlow: StateFlow<Boolean> = _isRunningFlow

        val isServiceRunning: Boolean
            get() = _isRunningFlow.value
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            AppLogger.log("[NET] Network online. Resuming proxy...")
            updateNotification("Active • Connected")
            engine?.start()
        }

        override fun onLost(network: Network) {
            val activeNet = connectivityManager.activeNetwork
            val caps = connectivityManager.getNetworkCapabilities(activeNet)
            val hasInternet = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

            if (!hasInternet) {
                AppLogger.log("[OFFLINE] No connection. Pausing proxy sockets...")
                updateNotification("Paused • Waiting for network")
                engine?.stop()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startServiceLogic()
            ACTION_STOP -> stopServiceLogic()
        }
        return START_STICKY
    }

    private fun startServiceLogic() {
        if (_isRunningFlow.value) return
        _isRunningFlow.value = true

        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "TgUnlocker::ProxyWakeLock"
            ).apply {
                setReferenceCounted(false)
                acquire(24 * 60 * 60 * 1000L)
            }
        } catch (e: Exception) {
            AppLogger.log("[WARN] WakeLock acquire failed: ${e.message}")
        }

        val prefs = getSharedPreferences("tgunlocker_prefs", Context.MODE_PRIVATE)
        val port = prefs.getInt("pref_port", 1080)
        val customCdn = prefs.getString("pref_cdn", null)?.trim()?.ifEmpty { null }

        AppLogger.log("[INIT] Starting TgUnlocker on port $port...")
        val currentEngine = WsTunnelEngine(localPort = port, customDomain = customCdn)
        engine = currentEngine

        val notification = buildNotification("Active • Connected")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        currentEngine.start()

        serviceScope.launch {
            StickyBalancer.updateFromGitHub()
            val pingResult = currentEngine.testConnection()
            AppLogger.log("[PING] $pingResult")

            withContext(Dispatchers.Main) {
                Toast.makeText(applicationContext, pingResult, Toast.LENGTH_SHORT).show()
            }
        }

        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
            isNetworkRegistered = true
        } catch (e: Exception) {
            AppLogger.log("[WARN] Network callback failed: ${e.message}")
        }
    }

    private fun stopServiceLogic() {
        _isRunningFlow.value = false

        if (isNetworkRegistered) {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback)
            } catch (_: Exception) {}
            isNetworkRegistered = false
        }

        engine?.stop()
        engine = null

        try {
            wakeLock?.let {
                if (it.isHeld) it.release()
            }
        } catch (_: Exception) {}
        wakeLock = null

        serviceScope.coroutineContext.cancelChildren()

        AppLogger.log("[STOP] Service stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "TgUnlocker Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Background tunnel for Telegram"
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, ProxyForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TgUnlocker")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentIntent(openAppIntent)
            .addAction(android.R.drawable.ic_media_pause, "Stop", stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopServiceLogic()
        serviceScope.cancel()
        super.onDestroy()
    }
}