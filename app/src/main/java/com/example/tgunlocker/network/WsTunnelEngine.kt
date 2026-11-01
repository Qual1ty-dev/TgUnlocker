package com.example.tgunlocker.network

import com.example.tgunlocker.AppLogger
import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select
import java.io.*
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.math.abs

class WsTunnelEngine(
    val localPort: Int = 1080,
    val customDomain: String? = null,
    val secretHex: String = DEFAULT_SECRET
) {
    companion object {
        const val DEFAULT_SECRET = "5afec0de1c0ffee1fa57d4741c0ffee1"

        val PROTO_TAG_ABRIDGED = byteArrayOf(0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte())
        val PROTO_TAG_INTERMEDIATE = byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
        val PROTO_TAG_SECURE = byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte())

        const val PROTO_ABRIDGED_INT = 0xEFEFEFEF.toInt()
        const val PROTO_INTERMEDIATE_INT = 0xEEEEEEEE.toInt()
        const val PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD.toInt()

        private val RESERVED_FIRST_BYTES = setOf(0xEF.toByte())
        private val RESERVED_CONTINUE = byteArrayOf(0, 0, 0, 0)
    }

    private var serverSocket: ServerSocket? = null
    private val isRunning = AtomicBoolean(false)
    private var engineScope: CoroutineScope? = null
    private val activeClients = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())

    private val secretBytes: ByteArray by lazy {
        secretHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    @Synchronized
    fun start() {
        if (isRunning.get()) return
        isRunning.set(true)

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        engineScope = scope

        scope.launch {
            try {
                val socket = ServerSocket(localPort, 50, java.net.InetAddress.getByName("127.0.0.1"))
                serverSocket = socket
                AppLogger.log("[OK] MTProto Bridge listening on 127.0.0.1:$localPort")

                while (isRunning.get() && !socket.isClosed) {
                    val clientSocket = try {
                        socket.accept()
                    } catch (e: SocketException) {
                        break
                    }
                    activeClients.add(clientSocket)
                    launch {
                        try {
                            handleClient(clientSocket)
                        } catch (_: Exception) {
                        } finally {
                            activeClients.remove(clientSocket)
                            closeQuietly(clientSocket)
                        }
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    AppLogger.log("[ERR] Port bind failed: ${e.message}")
                }
            }
        }
    }

    @Synchronized
    fun stop() {
        if (!isRunning.get()) return
        isRunning.set(false)

        try {
            serverSocket?.close()
        } catch (_: Exception) {}
        serverSocket = null

        for (client in activeClients) {
            closeQuietly(client)
        }
        activeClients.clear()

        engineScope?.cancel()
        engineScope = null
        AppLogger.log("[STOP] MTProto Bridge stopped")
    }

    private suspend fun handleClient(client: Socket) = withContext(Dispatchers.IO) {
        client.tcpNoDelay = true
        client.sendBufferSize = 256 * 1024
        client.receiveBufferSize = 256 * 1024
        val input = BufferedInputStream(client.getInputStream(), 256 * 1024)
        val output = BufferedOutputStream(client.getOutputStream(), 256 * 1024)

        val handshake = ByteArray(64)
        readFully(input, handshake)

        val decPrekeyAndIv = handshake.copyOfRange(8, 56)
        val decPrekey = decPrekeyAndIv.copyOfRange(0, 32)
        val decIv = decPrekeyAndIv.copyOfRange(32, 48)

        val decKey = sha256(decPrekey + secretBytes)
        val testDecryptor = createAesCtrCipher(decKey, decIv)
        val decrypted = testDecryptor.update(handshake)

        val protoTag = decrypted.copyOfRange(56, 60)
        val protoInt = when {
            protoTag.contentEquals(PROTO_TAG_ABRIDGED) -> PROTO_ABRIDGED_INT
            protoTag.contentEquals(PROTO_TAG_INTERMEDIATE) -> PROTO_INTERMEDIATE_INT
            protoTag.contentEquals(PROTO_TAG_SECURE) -> PROTO_PADDED_INTERMEDIATE_INT
            else -> return@withContext
        }

        val dcBuffer = ByteBuffer.wrap(decrypted, 60, 2).order(ByteOrder.LITTLE_ENDIAN)
        val dcIdx = dcBuffer.short.toInt()
        val dcId = abs(dcIdx)
        val isMedia = dcIdx < 0

        val dcTag = "DC$dcId${if (isMedia) "m" else ""}"
        val targetDc = if (dcId == 203) 2 else dcId

        val relayInit = generateRelayInit(protoTag, dcIdx.toShort())

        val cltDecKey = sha256(decPrekey + secretBytes)
        val cltDec = createAesCtrCipher(cltDecKey, decIv).apply { update(ByteArray(64)) }

        val cltEncReversed = decPrekeyAndIv.reversedArray()
        val cltEncKey = sha256(cltEncReversed.copyOfRange(0, 32) + secretBytes)
        val cltEnc = createAesCtrCipher(cltEncKey, cltEncReversed.copyOfRange(32, 48))

        val relayEncKey = relayInit.copyOfRange(8, 40)
        val relayEncIv = relayInit.copyOfRange(40, 56)
        val tgEnc = createAesCtrCipher(relayEncKey, relayEncIv).apply { update(ByteArray(64)) }

        val relayDecReversed = relayInit.copyOfRange(8, 56).reversedArray()
        val relayDecKey = relayDecReversed.copyOfRange(0, 32)
        val relayDecIv = relayDecReversed.copyOfRange(32, 48)
        val tgDec = createAesCtrCipher(relayDecKey, relayDecIv)

        val ws: RawWebSocket = try {
            if (!isMedia && (targetDc == 2 || targetDc == 4)) {
                try {
                    RawWebSocket.connect(
                        targetHost = "149.154.167.220",
                        domain = "kws$targetDc.web.telegram.org",
                        sni = "sprinthost.ru",
                        timeoutMs = 2500
                    ).also {
                        AppLogger.log("[REQ] $dcTag -> sprinthost.ru (Direct)")
                    }
                } catch (_: Exception) {
                    connectViaCf(targetDc, dcTag)
                }
            } else {
                connectViaCf(targetDc, dcTag)
            }
        } catch (e: Exception) {
            AppLogger.log("[WS_FAIL] $dcTag: ${e.message}")
            return@withContext
        }

        ws.send(relayInit)
        val splitter = MsgSplitter(relayInit, protoInt)

        val jobClientToWs = launch(Dispatchers.IO) {
            val buffer = ByteArray(65536)
            try {
                while (isRunning.get() && !client.isClosed && !ws.isClosed()) {
                    val read = input.read(buffer)
                    if (read == -1) {
                        val tail = splitter.flush()
                        if (tail.isNotEmpty()) ws.send(tail[0])
                        break
                    }
                    val plain = cltDec.update(buffer.copyOfRange(0, read))
                    val chunk = tgEnc.update(plain)
                    val parts = splitter.split(chunk)
                    for (part in parts) {
                        ws.send(part)
                    }
                }
            } catch (_: Exception) {}
        }

        val jobWsToClient = launch(Dispatchers.IO) {
            try {
                while (isRunning.get() && !client.isClosed && !ws.isClosed()) {
                    val data = ws.recv() ?: break
                    val plain = tgDec.update(data)
                    val toClient = cltEnc.update(plain)
                    synchronized(output) {
                        output.write(toClient)
                        output.flush()
                    }
                }
            } catch (_: Exception) {}
        }

        try {
            select<Unit> {
                jobClientToWs.onJoin {}
                jobWsToClient.onJoin {}
            }
        } finally {
            jobClientToWs.cancel()
            jobWsToClient.cancel()
            ws.close()
            closeQuietly(client)
        }
    }

    private suspend fun connectViaCf(dc: Int, tag: String): RawWebSocket {
        if (!customDomain.isNullOrBlank()) {
            val clean = customDomain
                .removePrefix("https://").removePrefix("http://")
                .removePrefix("wss://").removePrefix("ws://")
                .trimEnd('/')
            val customHost = if (clean.startsWith("kws")) clean else "kws$dc.$clean"

            return try {
                val ws = RawWebSocket.connect(
                    targetHost = customHost,
                    domain = customHost,
                    sni = customHost,
                    timeoutMs = 4000
                )
                AppLogger.log("[REQ] $tag -> $customHost (Custom)")
                ws
            } catch (e: Exception) {
                AppLogger.log("[ERR] Custom CDN failed: ${e.message}")
                throw e
            }
        }

        val primary = StickyBalancer.getDomainForDc(dc)
        val candidateList = mutableListOf(primary)
        candidateList.addAll(StickyBalancer.getAllDomains().filter { it != primary }.shuffled())

        var lastErr: Exception? = null
        for (domain in candidateList) {
            val cfHost = "kws$dc.$domain"
            try {
                val ws = RawWebSocket.connect(
                    targetHost = cfHost,
                    domain = cfHost,
                    sni = cfHost,
                    timeoutMs = 4000
                )
                if (domain != primary) {
                    StickyBalancer.reportFailure(dc, primary)
                }
                AppLogger.log("[REQ] $tag -> $cfHost (CF Relay)")
                return ws
            } catch (e: Exception) {
                lastErr = e
                StickyBalancer.reportFailure(dc, domain)
            }
        }
        throw lastErr ?: IOException("All CF domains unreachable")
    }

    suspend fun testConnection(): String = withContext(Dispatchers.IO) {
        val t0 = System.currentTimeMillis()

        if (!customDomain.isNullOrBlank()) {
            val clean = customDomain
                .removePrefix("https://").removePrefix("http://")
                .removePrefix("wss://").removePrefix("ws://")
                .trimEnd('/')
            val customHost = if (clean.startsWith("kws")) clean else "kws2.$clean"
            return@withContext try {
                val ws = RawWebSocket.connect(
                    targetHost = customHost,
                    domain = customHost,
                    sni = customHost,
                    timeoutMs = 4000
                )
                val ping = System.currentTimeMillis() - t0
                ws.close()
                "Custom CDN ($customHost): OK (${ping}ms)"
            } catch (e: Exception) {
                "Custom CDN failed: ${e.message}"
            }
        }

        try {
            val ws = RawWebSocket.connect(
                targetHost = "149.154.167.220",
                domain = "kws2.web.telegram.org",
                sni = "sprinthost.ru",
                timeoutMs = 3500
            )
            val ping = System.currentTimeMillis() - t0
            ws.close()
            "Direct (DC2 sprinthost): OK (${ping}ms)"
        } catch (e: Exception) {
            val t1 = System.currentTimeMillis()
            val cfDomain = StickyBalancer.getDomainForDc(2)
            try {
                val ws = RawWebSocket.connect(
                    targetHost = "kws2.$cfDomain",
                    domain = "kws2.$cfDomain",
                    sni = "kws2.$cfDomain",
                    timeoutMs = 4000
                )
                val ping = System.currentTimeMillis() - t1
                ws.close()
                "CF Relay ($cfDomain): OK (${ping}ms)"
            } catch (cfErr: Exception) {
                "Error: Direct (${e.message}), CF (${cfErr.message})"
            }
        }
    }

    private fun generateRelayInit(protoTag: ByteArray, dcIdx: Short): ByteArray {
        val random = SecureRandom()
        val rnd = ByteArray(64)
        while (true) {
            random.nextBytes(rnd)
            if (rnd[0] in RESERVED_FIRST_BYTES) continue
            if (rnd.copyOfRange(4, 8).contentEquals(RESERVED_CONTINUE)) continue
            break
        }

        val encKey = rnd.copyOfRange(8, 40)
        val encIv = rnd.copyOfRange(40, 56)
        val encryptor = createAesCtrCipher(encKey, encIv)

        val dcBytes = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(dcIdx).array()
        val tailRand = ByteArray(2).also { random.nextBytes(it) }
        val tailPlain = protoTag + dcBytes + tailRand

        val encryptedFull = encryptor.update(rnd)
        val keystreamTail = ByteArray(8) { i -> (encryptedFull[56 + i].toInt() xor rnd[56 + i].toInt()).toByte() }
        val encryptedTail = ByteArray(8) { i -> (tailPlain[i].toInt() xor keystreamTail[i].toInt()).toByte() }

        val result = rnd.copyOf()
        System.arraycopy(encryptedTail, 0, result, 56, 8)
        return result
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun createAesCtrCipher(key: ByteArray, iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher
    }

    private fun readFully(stream: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = stream.read(buffer, offset, buffer.size - offset)
            if (count == -1) throw SocketException("EOF reached")
            offset += count
        }
    }

    private fun closeQuietly(socket: Socket?) {
        try { socket?.close() } catch (_: Exception) {}
    }

    class MsgSplitter(relayInit: ByteArray, private val protoInt: Int) {
        private val decCipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
            val key = SecretKeySpec(relayInit.copyOfRange(8, 40), "AES")
            val iv = IvParameterSpec(relayInit.copyOfRange(40, 56))
            init(Cipher.ENCRYPT_MODE, key, iv)
            update(ByteArray(64))
        }
        private var cipherBuf = ByteArray(0)
        private var plainBuf = ByteArray(0)
        private var disabled = false

        fun split(chunk: ByteArray): List<ByteArray> {
            if (chunk.isEmpty()) return emptyList()
            if (disabled) return listOf(chunk)

            cipherBuf += chunk
            plainBuf += decCipher.update(chunk)

            val parts = mutableListOf<ByteArray>()
            var offset = 0
            val bufLen = cipherBuf.size

            while (offset < bufLen) {
                val avail = bufLen - offset
                val packetLen = nextPacketLen(offset, avail) ?: break
                if (packetLen <= 0) {
                    parts.add(cipherBuf.copyOfRange(offset, bufLen))
                    offset = bufLen
                    disabled = true
                    break
                }
                parts.add(cipherBuf.copyOfRange(offset, offset + packetLen))
                offset += packetLen
            }

            if (offset > 0) {
                cipherBuf = cipherBuf.copyOfRange(offset, cipherBuf.size)
                plainBuf = plainBuf.copyOfRange(offset, plainBuf.size)
            }
            return parts
        }

        fun flush(): List<ByteArray> {
            if (cipherBuf.isEmpty()) return emptyList()
            val tail = cipherBuf
            cipherBuf = ByteArray(0)
            plainBuf = ByteArray(0)
            return listOf(tail)
        }

        private fun nextPacketLen(offset: Int, avail: Int): Int? {
            if (avail <= 0) return null
            return when (protoInt) {
                PROTO_ABRIDGED_INT -> nextAbridgedLen(offset, avail)
                PROTO_INTERMEDIATE_INT, PROTO_PADDED_INTERMEDIATE_INT -> nextIntermediateLen(offset, avail)
                else -> 0
            }
        }

        private fun nextAbridgedLen(offset: Int, avail: Int): Int? {
            val first = plainBuf[offset].toInt() and 0xFF
            val headerLen: Int
            val payloadLen: Int
            if (first == 0x7F || first == 0xFF) {
                if (avail < 4) return null
                val b1 = plainBuf[offset + 1].toInt() and 0xFF
                val b2 = plainBuf[offset + 2].toInt() and 0xFF
                val b3 = plainBuf[offset + 3].toInt() and 0xFF
                payloadLen = (b1 or (b2 shl 8) or (b3 shl 16)) * 4
                headerLen = 4
            } else {
                payloadLen = (first and 0x7F) * 4
                headerLen = 1
            }
            if (payloadLen <= 0) return 0
            val packetLen = headerLen + payloadLen
            return if (avail < packetLen) null else packetLen
        }

        private fun nextIntermediateLen(offset: Int, avail: Int): Int? {
            if (avail < 4) return null
            val b0 = plainBuf[offset].toInt() and 0xFF
            val b1 = plainBuf[offset + 1].toInt() and 0xFF
            val b2 = plainBuf[offset + 2].toInt() and 0xFF
            val b3 = plainBuf[offset + 3].toInt() and 0xFF
            val payloadLen = (b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)) and 0x7FFFFFFF
            if (payloadLen <= 0) return 0
            val packetLen = 4 + payloadLen
            return if (avail < packetLen) null else packetLen
        }
    }

    class RawWebSocket(
        private val socket: Socket,
        private val input: InputStream,
        private val output: OutputStream
    ) {
        private val isClosed = AtomicBoolean(false)
        private val fragBuffer = ByteArrayOutputStream()

        fun isClosed(): Boolean = isClosed.get()

        companion object {
            private val sslContext = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf<TrustManager>(object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                }), SecureRandom())
            }

            suspend fun connect(
                targetHost: String,
                domain: String,
                sni: String,
                timeoutMs: Int = 4000
            ): RawWebSocket = withContext(Dispatchers.IO) {
                val rawSocket = Socket()
                rawSocket.tcpNoDelay = true
                rawSocket.sendBufferSize = 256 * 1024
                rawSocket.receiveBufferSize = 256 * 1024
                rawSocket.soTimeout = 0
                rawSocket.connect(InetSocketAddress(targetHost, 443), timeoutMs)

                val sslSocket = sslContext.socketFactory.createSocket(rawSocket, targetHost, 443, true) as SSLSocket
                val params = sslSocket.sslParameters
                params.serverNames = listOf(SNIHostName(sni))
                sslSocket.sslParameters = params
                sslSocket.startHandshake()

                val writer = BufferedOutputStream(sslSocket.outputStream, 256 * 1024)
                val reader = BufferedInputStream(sslSocket.inputStream, 256 * 1024)

                val keyBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP)
                val req = "GET /apiws HTTP/1.1\r\n" +
                        "Host: $domain\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: $wsKey\r\n" +
                        "Sec-WebSocket-Version: 13\r\n" +
                        "Sec-WebSocket-Protocol: binary\r\n\r\n"

                writer.write(req.toByteArray(Charsets.US_ASCII))
                writer.flush()

                val statusLine = readLine(reader) ?: throw IOException("Empty WS response")
                if (!statusLine.contains("101")) {
                    throw IOException("Handshake failed: $statusLine")
                }
                while (true) {
                    val line = readLine(reader) ?: break
                    if (line.isEmpty()) break
                }

                return@withContext RawWebSocket(sslSocket, reader, writer)
            }

            private fun readLine(input: InputStream): String? {
                val sb = StringBuilder()
                var prev = -1
                while (true) {
                    val b = input.read()
                    if (b == -1) return if (sb.isEmpty()) null else sb.toString()
                    if (prev == '\r'.code && b == '\n'.code) {
                        return sb.substring(0, sb.length - 1)
                    }
                    sb.append(b.toChar())
                    prev = b
                }
            }
        }

        fun send(data: ByteArray) {
            if (isClosed.get()) throw IOException("WebSocket closed")
            val len = data.size
            val mask = ByteArray(4).also { SecureRandom().nextBytes(it) }
            val masked = ByteArray(len) { i -> (data[i].toInt() xor mask[i % 4].toInt()).toByte() }

            synchronized(output) {
                output.write(0x82)
                when {
                    len < 126 -> output.write(0x80 or len)
                    len < 65536 -> {
                        output.write(0x80 or 126)
                        output.write((len shr 8) and 0xFF)
                        output.write(len and 0xFF)
                    }
                    else -> {
                        output.write(0x80 or 127)
                        val bb = ByteBuffer.allocate(8).putLong(len.toLong()).array()
                        output.write(bb)
                    }
                }
                output.write(mask)
                output.write(masked)
                output.flush()
            }
        }

        fun recv(): ByteArray? {
            while (!isClosed.get()) {
                val b0 = input.read()
                val b1 = input.read()
                if (b0 == -1 || b1 == -1) return null

                val fin = (b0 and 0x80) != 0
                val opcode = b0 and 0x0F
                val hasMask = (b1 and 0x80) != 0
                var len = (b1 and 0x7F).toLong()

                if (len == 126L) {
                    val high = input.read()
                    val low = input.read()
                    if (high == -1 || low == -1) return null
                    len = ((high shl 8) or low).toLong()
                } else if (len == 127L) {
                    val lenBytes = ByteArray(8)
                    readExact(lenBytes)
                    len = ByteBuffer.wrap(lenBytes).long
                }

                val mask = if (hasMask) ByteArray(4).also { readExact(it) } else null
                val payload = ByteArray(len.toInt())
                readExact(payload)

                if (mask != null) {
                    for (i in payload.indices) {
                        payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
                    }
                }

                when (opcode) {
                    0x08 -> {
                        close()
                        return null
                    }
                    0x09 -> {
                        synchronized(output) {
                            output.write(byteArrayOf(0x8A.toByte(), 0x80.toByte(), 0, 0, 0, 0))
                            output.flush()
                        }
                        continue
                    }
                    0x0A -> continue
                    0x00, 0x01, 0x02 -> {
                        if (fin && fragBuffer.size() == 0) {
                            return payload
                        }
                        fragBuffer.write(payload)
                        if (fragBuffer.size() > 16 * 1024 * 1024) {
                            throw IOException("WS frame exceeded bound")
                        }
                        if (!fin) {
                            continue
                        }
                        val fullMessage = fragBuffer.toByteArray()
                        fragBuffer.reset()
                        return fullMessage
                    }
                }
            }
            return null
        }

        private fun readExact(target: ByteArray) {
            var off = 0
            while (off < target.size) {
                val r = input.read(target, off, target.size - off)
                if (r == -1) throw EOFException("Unexpected WS EOF")
                off += r
            }
        }

        fun close() {
            if (isClosed.compareAndSet(false, true)) {
                try {
                    synchronized(output) {
                        output.write(byteArrayOf(0x88.toByte(), 0x80.toByte(), 0, 0, 0, 0))
                        output.flush()
                    }
                } catch (_: Exception) {}
                try { socket.close() } catch (_: Exception) {}
            }
        }
    }
}
