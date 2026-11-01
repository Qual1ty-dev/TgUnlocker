package com.example.tgunlocker.network

import com.example.tgunlocker.AppLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

object StickyBalancer {
    private const val GITHUB_DOMAINS_URL =
        "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

    private val domains = CopyOnWriteArrayList(
        listOf(
            "pclead.co.uk",
            "offshor.co.uk",
            "cakeisalie.co.uk"
        )
    )

    private val dcToDomain = ConcurrentHashMap<Int, String>()

    fun getDomainForDc(dc: Int): String {
        return dcToDomain.computeIfAbsent(dc) {
            domains.randomOrNull() ?: "pclead.co.uk"
        }
    }

    fun getAllDomains(): List<String> = domains.toList()

    fun reportFailure(dc: Int, failedDomain: String) {
        val current = dcToDomain[dc]
        if (current == failedDomain) {
            val candidates = domains.filter { it != failedDomain }
            if (candidates.isNotEmpty()) {
                val next = candidates.random()
                dcToDomain[dc] = next
                AppLogger.log("[BALANCER] DC$dc switched: $failedDomain -> $next")
            }
        }
    }

    private fun decodeDomain(encoded: String): String {
        if (!encoded.endsWith(".com")) return encoded
        val prefix = encoded.dropLast(4)
        val n = prefix.count { it.isLetter() }
        val sb = StringBuilder()
        for (c in prefix) {
            if (c.isLetter()) {
                val base = if (c >= 'a') 'a'.code else 'A'.code
                val shifted = Math.floorMod(c.code - base - n, 26)
                sb.append((base + shifted).toChar())
            } else {
                sb.append(c)
            }
        }
        return sb.toString() + ".co.uk"
    }

    suspend fun updateFromGitHub() = withContext(Dispatchers.IO) {
        try {
            val url = URL("$GITHUB_DOMAINS_URL?t=${System.currentTimeMillis()}")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 7000
                readTimeout = 7000
                setRequestProperty("User-Agent", "TgUnlocker-Android")
            }
            if (conn.responseCode == 200) {
                val text = conn.inputStream.bufferedReader().readText()
                val fetched = text.lines()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { decodeDomain(it) }
                    .filter { it.contains(".") && it.length > 5 }

                if (fetched.size >= 3) {
                    val fresh = fetched.distinct()
                    domains.clear()
                    domains.addAll(fresh)
                    AppLogger.log("[BALANCER] Mirrors updated from GitHub (${domains.size} active)")
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
    }
}