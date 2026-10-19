package org.videolan.vlc.util.smb

import java.net.URI
import java.util.Locale

/** A decoded path confined to one SMB share. Never contains a password. */
internal data class SmbPath private constructor(
    val host: String,
    val port: Int,
    val share: String,
    val segments: List<String>,
    val user: String?
) {
    val relativePath: String get() = segments.joinToString("\\")
    val name: String get() = segments.lastOrNull().orEmpty()
    val parent: SmbPath get() = copy(segments = segments.dropLast(1))
    val displayPath: String get() = (listOf(share) + segments).joinToString("/", "/")

    fun child(name: String): SmbPath {
        validateName(name)
        return copy(segments = segments + name)
    }

    fun sameShare(other: SmbPath) = host == other.host && port == other.port &&
        share.equals(other.share, true) && user == other.user

    fun sameFile(other: SmbPath) = host == other.host && port == other.port &&
        share.equals(other.share, true) && segments == other.segments

    fun destination(folder: SmbPath, name: String): SmbPath {
        require(segments.isNotEmpty() && sameShare(folder))
        return folder.child(name).also { require(it.segments != segments) }
    }

    fun toUri(): String = URI("smb", user, host, if (port == 445) -1 else port,
        displayPath, null, null).toASCIIString()

    companion object {
        fun parse(value: String): SmbPath {
            val uri = URI(value)
            require(uri.scheme.equals("smb", true) && uri.host != null)
            require(uri.rawQuery == null && uri.rawFragment == null)
            require(uri.userInfo?.contains(':') != true)
            val port = if (uri.port == -1) 445 else uri.port
            require(port in 1..65535)
            val rawParts = uri.rawPath.orEmpty().removePrefix("/").removeSuffix("/").split('/')
            require(rawParts.isNotEmpty())
            val parts = rawParts.map { part ->
                // URI decoding preserves literal '+', unlike form URL decoding.
                URI("/$part").path.removePrefix("/").also { validateName(it) }
            }
            return SmbPath(uri.host.removeSurrounding("[", "]").lowercase(Locale.ROOT), port, parts.first(), parts.drop(1), uri.userInfo)
        }

        fun validateName(name: String) {
            require(name.isNotBlank() && name != "." && name != "..")
            require(name.length <= 255 && !name.endsWith('.') && !name.endsWith(' '))
            require(name.none { it < ' ' || it in "\\/:*?\"<>|" || it == '\u007f' })
        }
    }
}
