package org.videolan.vlc.util.smb

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class VlcCredentialRecordTest {
    private val path = SmbPath.parse("smb://nas/Media/video.mkv")
    private fun record(vararg values: Pair<String, String>) = VlcCredentialRecord(
        mapOf("protocol" to "smb", "server" to "nas", "port" to "445", "user" to "alice", "path" to "/Media") + values,
        byteArrayOf(1, 2, 3))

    @Test fun parsesNativeFileFormatWithoutTreatingPlusAsSpace() {
        val values = mapOf("protocol" to "smb", "user" to "测试+user", "server" to "nas", "path" to "/Media")
        val line = values.entries.joinToString(",", "{", "}:") {
            it.key + ":" + Base64.getEncoder().encodeToString(it.value.toByteArray())
        } + "AQID"
        val parsed = VlcCredentialRecord.parse(line) { Base64.getDecoder().decode(it) }
        assertEquals(values, parsed.values)
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.secret)
    }

    @Test fun rejectsOtherServersPortsProtocolsAndSiblingShares() {
        listOf(record("server" to "other"), record("port" to "1445"), record("port" to "invalid"),
            record("protocol" to "ftp"), record("path" to "/Media2"), record("path" to "/Other")).forEach {
            assertThrows(MissingSmbCredentials::class.java) { VlcCredentialRecord.select(listOf(it), path) }
        }
    }

    @Test fun selectsShareCredentialAheadOfServerCredentialAndNeverGuessesAnAccount() {
        val exact = record()
        assertSame(exact, VlcCredentialRecord.select(listOf(record("path" to "/"), exact), path))
        assertThrows(MissingSmbCredentials::class.java) {
            VlcCredentialRecord.select(listOf(exact, record("user" to "bob")), path)
        }
        assertSame(exact, VlcCredentialRecord.select(listOf(exact, record("user" to "bob")),
            SmbPath.parse("smb://alice@nas/Media/video.mkv")))
    }

    @Test fun domainMustMatchWhenSpecified() {
        assertThrows(MissingSmbCredentials::class.java) {
            VlcCredentialRecord.select(listOf(record("realm" to "OTHER")),
                SmbPath.parse("smb://WORK;alice@nas/Media/video.mkv"))
        }
    }

    @Test fun malformedOrDuplicateFieldsAreRejected() {
        listOf("broken", "{}:AQID", "{user:YWxpY2U=,user:Ym9i}:AQID", "{unknown:eA==}:AQID").forEach {
            assertThrows(IllegalArgumentException::class.java) {
                VlcCredentialRecord.parse(it) { value -> Base64.getDecoder().decode(value) }
            }
        }
    }
}
