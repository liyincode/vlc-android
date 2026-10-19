package org.videolan.vlc.util.smb

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

class NetbiosNameQueryTest {
    private val host = "media-box"
    private val id = 0x1234
    private fun reply(): ByteArray {
        val question = NetbiosNameQuery.request(host, id)
        return (question + byteArrayOf(0xc0.toByte(), 12, 0, 0x20, 0, 1, 0, 0, 0, 30, 0, 6,
            0, 0, 192.toByte(), 0, 2, 40)).apply {
            this[2] = 0x85.toByte(); this[3] = 0
            this[7] = 1
        }
    }

    @Test fun buildsFileServerQueryWithNameTransactionAndBroadcastFlag() {
        val query = NetbiosNameQuery.request(host, id)
        assertEquals(50, query.size)
        assertEquals(0x12, query[0].toInt())
        assertEquals(0x34, query[1].toInt())
        assertEquals(0x10, query[3].toInt())
        assertEquals(32, query[12].toInt())
        assertEquals("CA", String(query, 43, 2, Charsets.US_ASCII)) // suffix 0x20
        assertEquals(0x20, query[47].toInt())
    }

    @Test fun acceptsValidCompressedAnswerAndIgnoresQuestionCaseInTheCaller() {
        assertEquals(setOf(InetAddress.getByName("192.0.2.40")),
            NetbiosNameQuery.response(reply(), host.uppercase(), id))
    }

    @Test fun acceptsAuthoritativeAnswerWithoutAnEchoedQuestionFromMultihomedServers() {
        val question = NetbiosNameQuery.request(host, id)
        val header = question.copyOf(12).apply {
            this[2] = 0x85.toByte(); this[3] = 0x80.toByte()
            this[5] = 0; this[7] = 1
        }
        val response = header + question.copyOfRange(12, 50) +
            byteArrayOf(0, 0, 0, 30, 0, 6, 0, 0, 192.toByte(), 0, 2, 41)
        assertEquals(setOf(InetAddress.getByName("192.0.2.41")),
            NetbiosNameQuery.response(response, host, id))
    }

    @Test fun rejectsWrongTransactionNameErrorResponseAndGroupName() {
        assertTrue(NetbiosNameQuery.response(reply(), host, id + 1).isEmpty())
        assertTrue(NetbiosNameQuery.response(reply(), "other", id).isEmpty())
        listOf(reply().apply { this[3] = 3 }, reply().apply { this[2] = 7 },
            reply().apply { this[2] = 0x87.toByte() }, // truncated
            reply().apply { this[62] = 0x80.toByte() }).forEach {
            assertTrue(NetbiosNameQuery.response(it, host, id).isEmpty())
        }
    }

    @Test fun rejectsTruncatedPacketsInvalidRecordLengthsAndCompressionLoops() {
        val valid = reply()
        for (length in valid.indices) assertTrue(NetbiosNameQuery.response(valid.copyOf(length), host, id).isEmpty())
        listOf(valid.copyOf().apply { this[61] = 7 },
            valid.copyOf().apply { this[51] = 50 }, // pointer back to itself
            valid.copyOf().apply { this[50] = 0xff.toByte(); this[51] = 0xff.toByte() },
            valid.copyOf().apply { this[12] = 64 }).forEach {
            assertTrue(NetbiosNameQuery.response(it, host, id).isEmpty())
        }
    }

    @Test fun onlyShortAsciiNetbiosNamesUseLocalBroadcast() {
        listOf("192.0.2.40", "nas.local", "2001:db8::1", "too-long-netbios-name", "私有服务器", "*").forEach {
            assertFalse(NetbiosNameQuery.supports(it))
        }
        assertTrue(NetbiosNameQuery.supports("MEDIA-BOX"))
        assertTrue(SmbServerResolver.isAddress("192.0.2.40"))
        assertTrue(SmbServerResolver.isAddress("2001:db8::1"))
        assertFalse(SmbServerResolver.isAddress("999.0.2.40"))
    }
}
