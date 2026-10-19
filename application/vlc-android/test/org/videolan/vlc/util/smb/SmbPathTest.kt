package org.videolan.vlc.util.smb

import org.junit.Assert.*
import org.junit.Test

class SmbPathTest {
    @Test fun preservesUnicodeSpacesAndLiteralPlus() {
        val path = SmbPath.parse("smb://NAS/Media/%E7%94%B5%E5%BD%B1/a%20b+100%25.mkv")
        assertEquals("电影\\a b+100%.mkv", path.relativePath)
        assertEquals(path, SmbPath.parse(path.toUri()))
        assertEquals("smb://nas/Media/%E7%94%B5%E5%BD%B1/a%20b+100%25.mkv", path.toUri())
    }

    @Test fun rejectsTraversalAndUnsafeNames() {
        listOf("", " ", ".", "..", "a/b", "a\\b", "a:b", "a\u0000b", "a?b", "a.", "a ", "x".repeat(256)).forEach {
            assertThrows(IllegalArgumentException::class.java) { SmbPath.validateName(it) }
        }
        listOf("smb://nas/Media/%2e%2e/x", "smb://nas/Media/a%2fb", "smb://nas/Media/a%5cb",
            "smb://nas/Media//x", "smb://nas/Media/a?b", "smb://nas/Media/a#b", "smb://nas/",
            "smb://alice:secret@nas/Media/x", "smb://nas:0/Media/x").forEach {
            assertThrows(IllegalArgumentException::class.java) { SmbPath.parse(it) }
        }
    }

    @Test fun confinesMovesToSameHostPortShareAndAccount() {
        val source = SmbPath.parse("smb://nas/Media/a.mkv")
        listOf("smb://other/Media/", "smb://nas:1445/Media/", "smb://nas/Other/", "smb://bob@nas/Media/").forEach {
            assertThrows(IllegalArgumentException::class.java) { source.destination(SmbPath.parse(it), source.name) }
        }
        assertThrows(IllegalArgumentException::class.java) { source.destination(source.parent, source.name) }
        assertEquals("folder\\a.mkv", source.destination(source.parent.child("folder"), source.name).relativePath)
        assertEquals(source.parent, source.parent.parent)
    }

    @Test fun supportsIpv6AndExplicitPort() {
        val source = SmbPath.parse("smb://[::1]:1445/Media/a.mkv")
        assertEquals(1445, source.port)
        assertEquals(source, SmbPath.parse(source.toUri()))
    }

    @Test fun playingFileIdentityDoesNotDependOnUsernameInUrl() {
        assertTrue(SmbPath.parse("smb://tester@NAS:445/Media/video.mp4")
            .sameFile(SmbPath.parse("smb://nas/Media/video.mp4")))
        assertFalse(SmbPath.parse("smb://nas/Media/video.mp4")
            .sameFile(SmbPath.parse("smb://nas/Other/video.mp4")))
    }
}
