package org.videolan.vlc.util.smb

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.Locale

/** Resolves saved server entries, never using a media URL as a source of credentials. */
internal object SmbServerResolver {
    fun isAddress(host: String): Boolean = host.contains(':') ||
        host.split('.').let { parts -> parts.size == 4 && parts.all {
            it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255
        } }

    fun resolve(host: String): Set<InetAddress> {
        if (NetbiosNameQuery.supports(host)) {
            val local = runCatching { resolveNetbios(host) }.getOrDefault(emptySet())
            if (local.isNotEmpty()) return local
        }
        return runCatching { InetAddress.getAllByName(host).toSet() }.getOrDefault(emptySet())
    }

    private fun resolveNetbios(host: String): Set<InetAddress> {
        val id = SecureRandom().nextInt(65536)
        val query = NetbiosNameQuery.request(host, id)
        DatagramSocket().use { socket ->
            socket.broadcast = true
            val broadcast = InetAddress.getByName("255.255.255.255")
            // Like VLC's native resolver, allow two seconds for local discovery.
            // Retry the read-only query once if Wi-Fi loses the first datagram.
            repeat(2) { attempt ->
                socket.send(DatagramPacket(query, query.size, broadcast, 137))
                val deadline = System.nanoTime() + if (attempt == 0) 500_000_000L else 1_500_000_000L
                while (true) {
                    val remaining = deadline - System.nanoTime()
                    if (remaining <= 0) break
                    socket.soTimeout = ((remaining + 999_999) / 1_000_000).toInt().coerceAtLeast(1)
                    val packet = DatagramPacket(ByteArray(4096), 4096)
                    try {
                        socket.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        break
                    }
                    if (packet.port != 137) continue
                    val addresses = NetbiosNameQuery.response(packet.data.copyOf(packet.length), host, id)
                    // Multihomed servers can reply from a different interface than NB_ADDRESS.
                    if (addresses.isNotEmpty()) return addresses
                }
            }
            return emptySet()
        }
    }
}

/** RFC 1002 NAME QUERY, file-server suffix 0x20; malformed replies are ignored. */
internal object NetbiosNameQuery {
    fun supports(host: String) = host.length in 1..15 && host.any { it.isLetter() } &&
        host.all { it.code in 33..126 && it !in ".:/\\[]*" }

    private fun name(host: String): String {
        require(supports(host))
        val raw = host.uppercase(Locale.ROOT).padEnd(15, ' ') + ' '
        return buildString(32) { raw.forEach {
            append('A' + (it.code shr 4)); append('A' + (it.code and 15))
        } }
    }

    fun request(host: String, id: Int): ByteArray {
        val encoded = name(host).toByteArray(Charsets.US_ASCII)
        return ByteArray(50).apply {
            this[0] = (id shr 8).toByte(); this[1] = id.toByte()
            this[2] = 0x01; this[3] = 0x10 // recursion desired + broadcast
            this[5] = 1 // one question
            this[12] = 32
            encoded.copyInto(this, 13)
            this[46] = 0; this[47] = 0x20 // NB
            this[48] = 0; this[49] = 1 // IN
        }
    }

    fun response(data: ByteArray, host: String, id: Int): Set<InetAddress> = runCatching {
        fun word(offset: Int): Int {
            require(offset >= 0 && offset + 1 < data.size)
            return ((data[offset].toInt() and 255) shl 8) or (data[offset + 1].toInt() and 255)
        }
        fun readName(start: Int): Pair<String, Int> {
            var position = start
            var end = -1
            val seen = mutableSetOf<Int>()
            val output = ByteArrayOutputStream()
            while (true) {
                require(position in data.indices && seen.add(position) && seen.size <= 64)
                val size = data[position].toInt() and 255
                if (size == 0) return output.toString("US-ASCII") to if (end < 0) position + 1 else end
                if (size and 0xc0 == 0xc0) {
                    val pointer = word(position) and 0x3fff
                    if (end < 0) end = position + 2
                    position = pointer
                } else {
                    require(size in 1..63 && position + size < data.size && output.size() + size <= 255)
                    if (output.size() != 0) output.write('.'.code)
                    output.write(data, position + 1, size)
                    position += size + 1
                }
            }
        }
        require(data.size >= 12 && word(0) == id)
        val flags = word(2)
        require(flags and 0x8000 != 0 && flags and 0x7a0f == 0)
        val questions = word(4)
        val answers = word(6)
        require(questions <= 1 && answers in 1..64)
        val expected = name(host)
        var position = 12
        repeat(questions) {
            val (label, next) = readName(position)
            require(label == expected && word(next) == 0x20 && word(next + 2) == 1)
            position = next + 4
        }
        val addresses = mutableSetOf<InetAddress>()
        repeat(answers) {
            val (label, next) = readName(position)
            val type = word(next)
            val clazz = word(next + 2)
            val length = word(next + 8)
            val start = next + 10
            require(start + length <= data.size)
            if (label == expected && type == 0x20 && clazz == 1) {
                require(length > 0 && length % 6 == 0)
                for (offset in start until start + length step 6) {
                    if (word(offset) and 0x8000 != 0) continue // group names cannot identify a server
                    val address = InetAddress.getByAddress(data.copyOfRange(offset + 2, offset + 6))
                    if (!address.isAnyLocalAddress && !address.isMulticastAddress &&
                        address.hostAddress != "255.255.255.255") addresses.add(address)
                }
            }
            position = start + length
        }
        addresses
    }.getOrDefault(emptySet())
}
