package org.videolan.vlc.util.smb

import android.content.Context
import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2CreateOptions
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.security.bc.BCSecurityProvider
import java.util.EnumSet
import java.util.concurrent.TimeUnit

/** Blocking operations. The caller owns IO dispatch and must not automatically retry a write. */
internal class SmbFileOperations(private val context: Context) {
    fun folders(path: SmbPath): List<String> = withShare(path) { share ->
        share.list(path.relativePath).filter {
            it.fileName != "." && it.fileName != ".." &&
                it.fileAttributes and FileAttributes.FILE_ATTRIBUTE_DIRECTORY.value != 0L &&
                it.fileAttributes and FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT.value == 0L
        }.map { it.fileName }.filter { runCatching { SmbPath.validateName(it) }.isSuccess }
            .sortedWith(String.CASE_INSENSITIVE_ORDER)
    }

    fun rename(source: SmbPath, target: SmbPath) {
        require(source.segments.isNotEmpty() && target.segments.isNotEmpty())
        require(source.sameShare(target) && source.segments != target.segments)
        withShare(source) { renameInShare(it, source, target) }
    }

    private fun <T> withShare(path: SmbPath, action: (DiskShare) -> T): T {
        VlcSmbCredentials.read(context, path).use { credentials ->
            val auth = AuthenticationContext(credentials.username, credentials.password, credentials.domain)
            try {
                val config = SmbConfig.builder().withTimeout(15, TimeUnit.SECONDS)
                    .withSoTimeout(15, TimeUnit.SECONDS).withSecurityProvider(BCSecurityProvider())
                    .withSigningRequired(true).withSocketFactory(credentials.target.socketFactory()).build()
                SMBClient(config).use { client ->
                    client.connect(credentials.target.server, credentials.target.port).use { connection ->
                        if (credentials.target.serverGuid?.let { it != connection.connectionContext.serverGuid } == true)
                            throw UnverifiedSmbServer()
                        connection.authenticate(auth).use { session ->
                            session.connectShare(path.share).use { share ->
                                require(share is DiskShare)
                                return action(share)
                            }
                        }
                    }
                }
            } finally {
                auth.password.fill('\u0000')
            }
        }
    }

    companion object {
        internal fun renameInShare(share: DiskShare, source: SmbPath, target: SmbPath) {
            require(source.sameShare(target) && source.segments.isNotEmpty() && target.segments.isNotEmpty())
            require(source.segments != target.segments)
            share.openFile(source.relativePath, EnumSet.of(AccessMask.DELETE), null,
                EnumSet.allOf(SMB2ShareAccess::class.java), SMB2CreateDisposition.FILE_OPEN,
                EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE, SMB2CreateOptions.FILE_OPEN_REPARSE_POINT)).use { file ->
                // The server enforces no replacement, including races with another client.
                file.rename(target.relativePath, false)
            }
        }
    }
}
