package org.videolan.vlc.util.smb

import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

internal class UnverifiedSmbServer : Exception()

/** The saved entry remains the authority; media aliases never become new login entries. */
internal data class SmbCredentialTarget(
    val record: VlcCredentialRecord,
    val server: String,
    val address: InetAddress,
    val port: Int,
    val serverGuid: UUID? = null
) {
    fun socketFactory(): SocketFactory = SmbServerSocketFactory(server, address, port)

    companion object {
        fun select(records: List<VlcCredentialRecord>, path: SmbPath,
                   identify: (String, InetAddress, Int) -> UUID? = SmbServerIdentity::probe,
                   resolve: (String) -> Set<InetAddress> = SmbServerResolver::resolve): SmbCredentialTarget {
            fun canonical(host: String) = host.removeSurrounding("[", "]").lowercase(Locale.ROOT)
            val eligible = VlcCredentialRecord.matching(records, path) { true }
            if (eligible.isEmpty()) throw MissingSmbCredentials()
            val exact = eligible.filter { canonical(it.values.getValue("server")) == path.host }
            val cache = mutableMapOf<String, Set<InetAddress>>()
            fun addresses(host: String) = cache.getOrPut(canonical(host)) { resolve(canonical(host)) }
            if (exact.isNotEmpty()) {
                // Never bypass an ambiguous exact login by falling back to another entry.
                val record = VlcCredentialRecord.select(exact, path)
                val server = canonical(record.values.getValue("server"))
                val address = addresses(server).firstOrNull() ?: throw UnverifiedSmbServer()
                return SmbCredentialTarget(record, server, address, path.port)
            }
            val requested = addresses(path.host)
            if (requested.isEmpty()) throw UnverifiedSmbServer()
            val identities = mutableMapOf<Pair<String, InetAddress>, UUID?>()
            fun identity(host: String, address: InetAddress) = identities.getOrPut(host to address) {
                identify(host, address, path.port)?.takeUnless { it == UUID(0, 0) }
            }
            val targets = mutableMapOf<VlcCredentialRecord, Pair<InetAddress, UUID?>>()
            val matches = eligible.filter { record ->
                val server = canonical(record.values.getValue("server"))
                // This fixes name <-> IP paths, without merging different named servers.
                if (SmbServerResolver.isAddress(server) == SmbServerResolver.isAddress(path.host)) return@filter false
                val resolved = addresses(server)
                val common = resolved.firstOrNull { it in requested }
                if (common != null) {
                    targets[record] = common to null
                    return@filter true
                }
                // A multi-interface NAS may advertise a different IP. Negotiate only:
                // never send saved credentials to the media address to test an alias.
                for (address in resolved) {
                    val guid = identity(server, address) ?: continue
                    val mediaAddress = requested.firstOrNull { identity(path.host, it) == guid }
                    if (mediaAddress != null) {
                        // Keep the saved server identity, but prefer the verified literal
                        // address over an alternate NIC or a DNS proxy's synthetic address.
                        targets[record] = (if (SmbServerResolver.isAddress(path.host)) mediaAddress else address) to guid
                        return@filter true
                    }
                }
                false
            }
            if (matches.isEmpty()) throw UnverifiedSmbServer()
            val record = VlcCredentialRecord.select(matches, path) { true }
            val server = canonical(record.values.getValue("server"))
            val (address, guid) = targets.getValue(record)
            return SmbCredentialTarget(record, server, address, path.port, guid)
        }
    }
}

/** Negotiation contains no authentication; a GUID is corroboration, not a password trust store. */
internal object SmbServerIdentity {
    fun probe(server: String, address: InetAddress, port: Int): UUID? = runCatching {
        val config = SmbConfig.builder().withTimeout(3, TimeUnit.SECONDS)
            .withSoTimeout(3, TimeUnit.SECONDS).withSecurityProvider(BCSecurityProvider())
            .withSocketFactory(SmbServerSocketFactory(server, address, port, 3_000)).build()
        SMBClient(config).use { client ->
            client.connect(server, port).use { it.connectionContext.serverGuid }
        }
    }.getOrNull()
}

private class SmbServerSocketFactory(private val server: String, private val address: InetAddress,
                                     private val port: Int, private val timeout: Int = 15_000) : SocketFactory() {
    private fun connect(host: String, remotePort: Int, local: InetSocketAddress? = null): Socket {
        require(host.removeSurrounding("[", "]").equals(server, true) && remotePort == port)
        val socket = Socket()
        try {
            if (local != null) socket.bind(local)
            socket.connect(InetSocketAddress(address, port), timeout)
            return socket
        } catch (error: Exception) {
            socket.close()
            throw error
        }
    }

    override fun createSocket(host: String, port: Int) = connect(host, port)
    override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int) =
        connect(host, port, InetSocketAddress(local, localPort))
    override fun createSocket(host: InetAddress, port: Int): Socket =
        throw UnsupportedOperationException("Use the saved server name")
    override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket =
        throw UnsupportedOperationException("Use the saved server name")
}
