package org.videolan.vlc.util.smb

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMBApiException
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import io.mockk.*
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class SmbFileOperationsTest {
    private val source = SmbPath.parse("smb://nas/Media/original.mkv")
    private val target = source.destination(source.parent.child("folder"), source.name)

    @Test fun opensOnlyExistingFileAndUsesServerEnforcedNoReplacement() {
        val share = mockk<DiskShare>()
        val file = mockk<File>()
        every { share.openFile("original.mkv", match { it == setOf(AccessMask.DELETE) }, null,
            any(), SMB2CreateDisposition.FILE_OPEN, any()) } returns file
        every { file.rename("folder\\original.mkv", false) } just Runs
        every { file.close() } just Runs

        SmbFileOperations.renameInShare(share, source, target)

        verifySequence {
            share.openFile("original.mkv", any(), null, any(), SMB2CreateDisposition.FILE_OPEN, any())
            file.rename("folder\\original.mkv", false)
            file.close()
        }
        confirmVerified(share, file)
    }

    @Test fun collisionAccessDeniedAndDisconnectNeverCauseRetryOrDelete() {
        listOf(
            SMBApiException(NtStatus.STATUS_OBJECT_NAME_COLLISION.value, SMB2MessageCommandCode.SMB2_SET_INFO, "collision", null),
            SMBApiException(NtStatus.STATUS_ACCESS_DENIED.value, SMB2MessageCommandCode.SMB2_SET_INFO, "denied", null),
            IOException("disconnected")
        ).forEach { error ->
            val share = mockk<DiskShare>()
            val file = mockk<File>()
            every { share.openFile(any(), any(), any(), any(), any(), any()) } returns file
            every { file.rename(any(), false) } throws error
            every { file.close() } just Runs
            assertThrows(error.javaClass) { SmbFileOperations.renameInShare(share, source, target) }
            verify(exactly = 1) { share.openFile(any(), any(), any(), any(), SMB2CreateDisposition.FILE_OPEN, any()) }
            verify(exactly = 1) { file.rename(target.relativePath, false) }
            verify(exactly = 1) { file.close() }
            confirmVerified(share, file)
        }
    }

    @Test fun rejectsCrossShareAndSamePathBeforeAnyNetworkCall() {
        val share = mockk<DiskShare>()
        listOf(source, SmbPath.parse("smb://nas/Other/original.mkv")).forEach {
            assertThrows(IllegalArgumentException::class.java) { SmbFileOperations.renameInShare(share, source, it) }
        }
        verify { share wasNot Called }
    }
}
