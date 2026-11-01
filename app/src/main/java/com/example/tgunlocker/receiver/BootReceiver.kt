package com.example.tgunlocker.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.example.tgunlocker.AppLogger
import com.example.tgunlocker.service.ProxyForegroundService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == "android.intent.action.QUICKBOOT_POWERON") {
            val prefs = context.getSharedPreferences("tgunlocker_prefs", Context.MODE_PRIVATE)
            val autoStart = prefs.getBoolean("pref_autostart", false)

            if (autoStart) {
                AppLogger.log("[BOOT] Device rebooted. Auto-starting TgUnlocker...")
                val serviceIntent = Intent(context, ProxyForegroundService::class.java).apply {
                    action = ProxyForegroundService.ACTION_START
                }
                try {
                    ContextCompat.startForegroundService(context, serviceIntent)
                } catch (e: Exception) {
                    AppLogger.log("[ERR] Failed to start service on boot: ${e.message}")
                }
            }
        }
    }
}