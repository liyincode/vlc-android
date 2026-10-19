package org.videolan.vlc.util.smb

import android.content.Context
import android.os.Build
import android.util.Base64
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

/** Compatibility reader for the pinned VLC 3.x file_crypt format; deliberately read-only. */
internal object VlcSmbCredentials {
    fun read(context: Context, path: SmbPath): SmbCredentials {
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        val file = File(context.getDir("keystore", Context.MODE_PRIVATE), "file")
        if (!file.isFile || file.length() > 1024 * 1024) throw MissingSmbCredentials()
        val records = try {
            val content = file.readText()
            if (!content.endsWith('\n')) throw MissingSmbCredentials()
            content.lineSequence().filter { it.isNotEmpty() }.map {
                VlcCredentialRecord.parse(it) { value -> Base64.decode(value, Base64.NO_WRAP) }
            }.toList()
        } catch (e: MissingSmbCredentials) {
            throw e
        } catch (_: Exception) {
            throw MissingSmbCredentials()
        }
        val target = SmbCredentialTarget.select(records, path)
        val record = target.record
        val decrypted = try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = keyStore.getKey("LibVLCAndroid", null) ?: throw MissingSmbCredentials()
            val secret = record.secret
            require(secret.size >= 36)
            val ivLength = ByteBuffer.wrap(secret, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
            require(ivLength == 16 && (secret.size - 20) % 16 == 0)
            Cipher.getInstance("AES/CBC/PKCS7Padding").apply {
                init(Cipher.DECRYPT_MODE, key, IvParameterSpec(secret, 4, ivLength))
            }.doFinal(secret, 20, secret.size - 20)
        } catch (_: Exception) {
            throw MissingSmbCredentials()
        }
        try {
            if (decrypted.isEmpty() || decrypted.last() != 0.toByte()) throw MissingSmbCredentials()
            return SmbCredentials(record.values.getValue("user"),
                String(decrypted, 0, decrypted.size - 1, Charsets.UTF_8).toCharArray(),
                record.values["realm"].orEmpty(), target)
        } finally {
            decrypted.fill(0)
            record.secret.fill(0)
        }
    }
}

internal class MissingSmbCredentials : Exception()

internal class SmbCredentials(val username: String, val password: CharArray, val domain: String,
                             val target: SmbCredentialTarget) : AutoCloseable {
    override fun close() = password.fill('\u0000')
}

internal class VlcCredentialRecord(val values: Map<String, String>, val secret: ByteArray) {
    companion object {
        fun parse(line: String, decode: (String) -> ByteArray): VlcCredentialRecord {
            require(line.startsWith('{') && line.count { it == '}' } == 1)
            val end = line.indexOf("}:")
            require(end > 1)
            val pairs = line.substring(1, end).split(',').map {
                val index = it.indexOf(':')
                require(index > 0)
                it.substring(0, index) to String(decode(it.substring(index + 1)), Charsets.UTF_8)
            }
            require(pairs.map { it.first }.distinct().size == pairs.size)
            require(pairs.all { it.first in setOf("protocol", "user", "server", "path", "port", "realm", "authtype") })
            return VlcCredentialRecord(pairs.toMap(), decode(line.substring(end + 2)))
        }

        fun matching(records: List<VlcCredentialRecord>, path: SmbPath,
                     serverMatches: (String) -> Boolean): List<VlcCredentialRecord> {
            val user = path.user?.substringAfter(';')
            val realm = path.user?.takeIf { ';' in it }?.substringBefore(';')
            return records.filter {
                val v = it.values
                val scope = v["path"]?.trimEnd('/')
                v["protocol"] == "smb" && !v["server"].isNullOrBlank() &&
                    (if (v["port"] == null) 445 else v["port"]?.toIntOrNull()) == path.port &&
                    !v["user"].isNullOrEmpty() && (user == null || user == v["user"]) &&
                    (realm == null || realm == v["realm"]) &&
                    (scope == null || scope.isEmpty() || scope == "/" || scope.equals("/${path.share}", true)) &&
                    serverMatches(v.getValue("server"))
            }
        }

        fun select(records: List<VlcCredentialRecord>, path: SmbPath,
                   serverMatches: (String) -> Boolean = { it.removeSurrounding("[", "]").equals(path.host, true) }): VlcCredentialRecord {
            val matches = matching(records, path, serverMatches)
            // A share-specific credential wins over a server-wide one. Never guess between accounts.
            val closest = matches.groupBy { it.values["path"]?.trimEnd('/')?.length ?: 0 }
                .maxByOrNull { it.key }?.value ?: throw MissingSmbCredentials()
            if (closest.size != 1) throw MissingSmbCredentials()
            return closest.single()
        }
    }
}
