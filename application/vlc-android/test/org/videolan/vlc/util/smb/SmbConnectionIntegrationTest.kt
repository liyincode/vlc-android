package org.videolan.vlc.util.smb

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2CreateOptions
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.DiskShare
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress
import java.util.EnumSet
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Opt-in, localhost-only fixture. Never takes production credentials or a remote host. */
class SmbConnectionIntegrationTest {
    @Test fun aliasConnectionUsesSignedOriginalServerSessionAndRenamesWithoutReplacing() {
        val port = System.getenv("VLC_SMB_TEST_PORT")?.toIntOrNull()
        assumeTrue("Requires the task's temporary local Samba fixture", port != null)
        require(port in 1024..65535)
        val source = SmbPath.parse("smb://127.0.0.1:$port/Test/vlc-alias-${UUID.randomUUID()}.txt")
        val target = source.parent.child(source.name + ".renamed")
        val saved = VlcCredentialRecord(mapOf("protocol" to "smb", "server" to "fixture-nas",
            "port" to "$port", "user" to "tester", "path" to "/Test"), byteArrayOf())
        val connectionTarget = SmbCredentialTarget.select(listOf(saved), source) {
            setOf(InetAddress.getByName("127.0.0.1"))
        }
        val config = SmbConfig.builder().withTimeout(5, TimeUnit.SECONDS).withSoTimeout(5, TimeUnit.SECONDS)
            .withSigningRequired(true).withSecurityProvider(BCSecurityProvider())
            .withSocketFactory(connectionTarget.socketFactory()).build()
        val auth = AuthenticationContext("tester", "test-only-password".toCharArray(), "")
        try {
            SMBClient(config).use { client ->
                client.connect(connectionTarget.server, connectionTarget.port).use { connection ->
                    assertEquals("fixture-nas", connection.remoteHostname)
                    connection.authenticate(auth).use { session ->
                        (session.connectShare("Test") as DiskShare).use { share ->
                            try {
                                share.openFile(source.relativePath, EnumSet.of(AccessMask.GENERIC_WRITE), null,
                                    EnumSet.allOf(SMB2ShareAccess::class.java), SMB2CreateDisposition.FILE_CREATE,
                                    EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE)).use { file ->
                                    val content = "temporary alias regression fixture".toByteArray()
                                    file.write(content, 0)
                                }
                                SmbFileOperations.renameInShare(share, source, target)
                                assertFalse(share.fileExists(source.relativePath))
                                assertTrue(share.fileExists(target.relativePath))
                            } finally {
                                listOf(source, target).forEach { if (share.fileExists(it.relativePath)) share.rm(it.relativePath) }
                            }
                        }
                    }
                }
            }
        } finally {
            auth.password.fill('\u0000')
        }
    }
}
