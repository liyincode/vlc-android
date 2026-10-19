package org.videolan.vlc.util.smb

import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMBApiException
import org.junit.Assert.assertEquals
import org.junit.Test
import org.videolan.vlc.R
import java.io.IOException

class SmbOperationErrorTest {
    @Test fun anUnverifiedServerIsAConfirmedPreWriteFailure() {
        assertEquals(R.string.smb_server_unverified, smbErrorMessage(UnverifiedSmbServer(), true))
        assertEquals(R.string.smb_server_unverified, smbErrorMessage(UnverifiedSmbServer(), false))
    }

    @Test fun recognizesReadOnlyStatusMissingFromLibraryEnum() {
        val error = SMBApiException(0xc00000a2L, SMB2MessageCommandCode.SMB2_SET_INFO, "fixture", null)
        assertEquals(R.string.smb_read_only, smbErrorMessage(error, true))
    }

    @Test fun disconnectDuringWriteMustNotBeReportedAsDefiniteFailure() {
        assertEquals(R.string.smb_operation_uncertain, smbErrorMessage(IOException(), true))
        assertEquals(R.string.smb_list_failed, smbErrorMessage(IOException(), false))
    }
}
