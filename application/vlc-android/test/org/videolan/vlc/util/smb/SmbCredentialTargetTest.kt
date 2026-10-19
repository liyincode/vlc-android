package org.videolan.vlc.util.smb

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.UUID

class SmbCredentialTargetTest {
    private val ip = InetAddress.getByName("192.0.2.40")
    private val other = InetAddress.getByName("192.0.2.41")
    private fun record(vararg values: Pair<String, String>) = VlcCredentialRecord(
        mapOf("protocol" to "smb", "server" to "home-nas", "port" to "445",
            "user" to "alice", "path" to "/Media") + values, byteArrayOf(1))
    private val path = SmbPath.parse("smb://192.0.2.40/Media/video.mkv")

    @Test fun nameLoginMatchesIpMediaButKeepsOriginalServerAndResolvedAddress() {
        val saved = record()
        val calls = mutableListOf<String>()
        val target = SmbCredentialTarget.select(listOf(saved), path) {
            calls.add(it); setOf(ip)
        }
        assertSame(saved, target.record)
        assertEquals("home-nas", target.server)
        assertEquals(ip, target.address)
        assertEquals(listOf("192.0.2.40", "home-nas"), calls)
    }

    @Test fun ipLoginAlsoMatchesNamedMedia() {
        val saved = record("server" to "192.0.2.40")
        val target = SmbCredentialTarget.select(listOf(saved),
            SmbPath.parse("smb://home-nas/Media/video.mkv")) { setOf(ip) }
        assertEquals("192.0.2.40", target.server)
        assertSame(saved, target.record)
    }

    @Test fun supportsIpv6AndPinsTheCommonAddressOnMultihomedServers() {
        val ipv6 = InetAddress.getByName("2001:db8::40")
        val target = SmbCredentialTarget.select(listOf(record()),
            SmbPath.parse("smb://[2001:db8::40]/Media/video.mkv")) {
            if (it.contains(':')) setOf(ipv6) else linkedSetOf(ip, ipv6)
        }
        assertEquals(ipv6, target.address)
        assertEquals("home-nas", target.server)
    }

    @Test fun mismatchedAndUnresolvableAddressesNeverSelectALogin() {
        listOf(emptySet(), setOf(other)).forEach { resolved ->
            assertThrows(UnverifiedSmbServer::class.java) {
                SmbCredentialTarget.select(listOf(record()), path, identify = { _, _, _ -> null }) {
                    if (it == path.host) setOf(ip) else resolved
                }
            }
        }
    }

    @Test fun differentInterfacesNeedTheSameNonzeroGuidAndKeepTheOriginalServerIdentity() {
        val guid = UUID(10, 20)
        val probes = mutableListOf<String>()
        val target = SmbCredentialTarget.select(listOf(record()), path,
            identify = { host, _, _ -> probes.add(host); guid }) {
            if (it == path.host) setOf(ip) else setOf(other)
        }
        assertEquals(ip, target.address)
        assertEquals("home-nas", target.server)
        assertEquals(guid, target.serverGuid)
        assertEquals(listOf("home-nas", path.host), probes)
        listOf<UUID?>(null, UUID(0, 0), UUID(30, 40)).forEach { wrong ->
            assertThrows(UnverifiedSmbServer::class.java) {
                SmbCredentialTarget.select(listOf(record()), path,
                    identify = { host, _, _ -> if (host == path.host) wrong else guid }) {
                    if (it == path.host) setOf(ip) else setOf(other)
                }
            }
        }
    }

    @Test fun aSyntheticDnsEndpointNeverReceivesCredentialsWhenTheVerifiedMediaIpIsAvailable() {
        val synthetic = InetAddress.getByName("198.18.0.2")
        val target = SmbCredentialTarget.select(listOf(record()), path,
            identify = { _, _, _ -> UUID(10, 20) }) {
            if (it == path.host) setOf(ip) else setOf(synthetic)
        }
        assertEquals("home-nas", target.server)
        assertEquals(ip, target.address)
        assertEquals(UUID(10, 20), target.serverGuid)
    }

    @Test fun differentNamesAreNotMergedJustBecauseDnsReturnsTheSameAddress() {
        assertThrows(UnverifiedSmbServer::class.java) {
            SmbCredentialTarget.select(listOf(record()),
                SmbPath.parse("smb://unrelated/Media/video.mkv")) { setOf(ip) }
        }
    }

    @Test fun exactLoginWinsAndAnAmbiguousExactLoginNeverFallsBack() {
        val exact = record("server" to path.host)
        assertSame(exact, SmbCredentialTarget.select(listOf(record(), exact), path) { setOf(ip) }.record)
        assertThrows(MissingSmbCredentials::class.java) {
            SmbCredentialTarget.select(listOf(exact, record("server" to path.host, "user" to "bob"), record()),
                path) { setOf(ip) }
        }
    }

    @Test fun aliasesRetainPortShareProtocolUsernameAndDomainBoundariesBeforeResolution() {
        listOf(record("port" to "1445"), record("path" to "/Other"), record("protocol" to "ftp"),
            record("user" to "bob"), record("realm" to "OTHER")).forEach { invalid ->
            assertThrows(MissingSmbCredentials::class.java) {
                SmbCredentialTarget.select(listOf(invalid),
                    SmbPath.parse("smb://WORK;alice@192.0.2.40/Media/video.mkv")) {
                    fail("Out-of-scope credentials must not trigger resolution"); emptySet()
                }
            }
        }
    }

    @Test fun multipleMatchingAccountsAreRejectedWithoutGuessingOrTryingPasswords() {
        assertThrows(MissingSmbCredentials::class.java) {
            SmbCredentialTarget.select(listOf(record(), record("server" to "second-nas", "user" to "bob")),
                path) { setOf(ip) }
        }
        val target = SmbCredentialTarget.select(listOf(record(), record("user" to "bob")),
            SmbPath.parse("smb://alice@192.0.2.40/Media/video.mkv")) { setOf(ip) }
        assertEquals("alice", target.record.values["user"])
    }

    @Test fun socketFactoryRejectsOtherHostsAndPortsAndDoesNotResolveAgain() {
        val local = InetAddress.getByName("127.0.0.1")
        ServerSocket(0, 1, local).use { listener ->
            listener.soTimeout = 1000
            val target = SmbCredentialTarget(record(), "saved.invalid", local, listener.localPort)
            val sockets = target.socketFactory()
            assertThrows(IllegalArgumentException::class.java) { sockets.createSocket("media.invalid", listener.localPort) }
            assertThrows(IllegalArgumentException::class.java) { sockets.createSocket("saved.invalid", listener.localPort + 1) }
            sockets.createSocket("saved.invalid", listener.localPort).use { client ->
                listener.accept().use { peer ->
                    assertEquals(local, client.inetAddress)
                    peer.getOutputStream().write(42)
                    assertEquals(42, client.getInputStream().read())
                }
            }
        }
    }
}
