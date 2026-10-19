/* Link against the final libvlc.so to exercise the packaged NetBIOS resolver. */
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bdsm/netbios_ns.h>
#include <bdsm/netbios_defs.h>

int main(void)
{
    alarm(15);
    int fd = -1;
    while (fd < 1100) {
        fd = open("/dev/null", O_RDONLY);
        assert(fd >= 0);
    }
    printf("Highest held descriptor: %d\n", fd);
    fflush(stdout);
    netbios_ns *ns = netbios_ns_new();
    assert(ns != NULL);
    uint32_t address;
    assert(netbios_ns_resolve(ns, "VLC-FD-TEST", NETBIOS_FILESERVER, &address) == -1);
    netbios_ns_destroy(ns);
    puts("PASS final VLC core: name resolution timed out without crashing");
    return 0;
}
