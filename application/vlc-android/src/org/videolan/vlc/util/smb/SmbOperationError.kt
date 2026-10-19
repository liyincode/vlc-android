package org.videolan.vlc.util.smb

import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMBApiException
import org.videolan.vlc.R

internal fun smbErrorMessage(error: Exception, writing: Boolean): Int = when (error) {
    is MissingSmbCredentials -> R.string.smb_login_required
    is UnverifiedSmbServer -> R.string.smb_server_unverified
    is SMBApiException -> when (error.statusCode) {
        NtStatus.STATUS_OBJECT_NAME_COLLISION.value -> R.string.smb_name_exists
        NtStatus.STATUS_ACCESS_DENIED.value -> R.string.smb_access_denied
        // MS-ERREF STATUS_MEDIA_WRITE_PROTECTED is not in SMBJ's NtStatus enum.
        0xc00000a2L -> R.string.smb_read_only
        NtStatus.STATUS_LOGON_FAILURE.value -> R.string.smb_login_failed
        NtStatus.STATUS_OBJECT_NAME_NOT_FOUND.value, NtStatus.STATUS_OBJECT_PATH_NOT_FOUND.value -> R.string.smb_file_missing
        NtStatus.STATUS_SHARING_VIOLATION.value -> R.string.smb_file_in_use
        else -> if (writing) R.string.smb_operation_uncertain else R.string.smb_list_failed
    }
    else -> if (writing) R.string.smb_operation_uncertain else R.string.smb_list_failed
}
