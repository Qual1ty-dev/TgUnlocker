package com.example.tgunlocker

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object AppLogger {
    private const val MAX_LOGS = 100
    private val buffer = ArrayDeque<String>(MAX_LOGS)
    private var listener: ((String) -> Unit)? = null
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    @Synchronized
    fun log(message: String) {
        val timestamp = timeFormat.format(Date())
        val entry = "[$timestamp] $message"

        if (buffer.size >= MAX_LOGS) {
            buffer.removeFirst()
        }
        buffer.addLast(entry)

        val fullText = buffer.joinToString("\n")
        listener?.invoke(fullText)
    }

    @Synchronized
    fun setListener(l: ((String) -> Unit)?) {
        listener = l
        if (buffer.isNotEmpty()) {
            listener?.invoke(buffer.joinToString("\n"))
        }
    }

    @Synchronized
    fun getLogs(): String = buffer.joinToString("\n")

    @Synchronized
    fun clear() {
        buffer.clear()
        listener?.invoke("")
    }
}