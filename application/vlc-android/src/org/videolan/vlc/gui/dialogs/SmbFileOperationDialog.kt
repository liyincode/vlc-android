package org.videolan.vlc.gui.dialogs

import android.app.Application
import android.app.Dialog
import android.content.DialogInterface
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.os.bundleOf
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import androidx.fragment.app.viewModels
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.videolan.medialibrary.interfaces.Medialibrary
import org.videolan.vlc.R
import org.videolan.vlc.media.PlaylistManager
import org.videolan.vlc.util.smb.smbErrorMessage
import org.videolan.vlc.util.smb.SmbFileOperations
import org.videolan.vlc.util.smb.SmbPath

const val SMB_FILE_OPERATION_RESULT = "smb_file_operation_result"
const val SMB_FILE_OPERATION_MESSAGE = "smb_file_operation_message"

/** Keeps the selected source immutable while the browser list refreshes behind the dialog. */
class SmbFileOperationDialog : DialogFragment() {
    private val model: SmbFileOperationModel by viewModels()
    private lateinit var name: EditText
    private lateinit var status: TextView
    private lateinit var path: TextView
    private lateinit var parent: Button
    private lateinit var retry: Button
    private lateinit var folders: ListView
    private val moving get() = requireArguments().getBoolean("moving")

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        model.initialize(requireArguments().getString("source")!!, moving,
            savedInstanceState?.getBoolean("operation_pending") == true)
        val context = requireContext()
        val padding = (24 * resources.displayMetrics.density).toInt()
        val body = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding / 2, padding, 0)
        }
        name = EditText(context).apply {
            inputType = InputType.TYPE_CLASS_TEXT
            isSingleLine = true
            setText(model.name)
            val end = model.name.lastIndexOf('.').takeIf { it > 0 } ?: model.name.length
            setSelection(0, end)
            visibility = if (moving) View.GONE else View.VISIBLE
        }
        path = TextView(context)
        parent = Button(context).apply { setText(R.string.smb_parent_folder) }
        folders = ListView(context)
        status = TextView(context).apply { setPadding(0, padding / 2, 0, padding / 2) }
        retry = Button(context).apply {
            setText(R.string.smb_retry)
            setOnClickListener { model.folder?.let { model.loadFolder(it) } }
        }
        body.addView(name)
        if (moving) body.addView(TextView(context).apply {
            text = model.name
            setPadding(0, 0, 0, padding / 2)
        })
        body.addView(path)
        body.addView(parent)
        body.addView(folders, LinearLayout.LayoutParams(-1, (200 * resources.displayMetrics.density).toInt()))
        body.addView(status)
        body.addView(retry)
        if (!moving) listOf(path, parent, folders).forEach { it.visibility = View.GONE }
        parent.setOnClickListener { model.folder?.let { model.loadFolder(it.parent) } }
        folders.setOnItemClickListener { _, _, position, _ ->
            val state = model.state.value ?: return@setOnItemClickListener
            model.folder?.let { model.loadFolder(it.child(state.folders[position])) }
        }
        model.state.observe(this) { render(it) }
        return AlertDialog.Builder(context)
            .setTitle(if (moving) R.string.smb_move else R.string.rename)
            .setView(body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(if (moving) R.string.smb_move_here else R.string.rename, null)
            .create()
    }

    override fun onStart() {
        super.onStart()
        (dialog as AlertDialog).getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            model.name = name.text.toString()
            model.execute()
        }
        model.state.value?.let { render(it) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        model.name = name.text.toString()
        outState.putBoolean("operation_pending", model.writing || model.state.value?.uncertain == true)
        super.onSaveInstanceState(outState)
    }

    override fun onDismiss(dialog: DialogInterface) {
        if (model.state.value?.uncertain == true) {
            setFragmentResult(SMB_FILE_OPERATION_RESULT, Bundle())
        }
        super.onDismiss(dialog)
    }

    private fun render(state: SmbOperationState) {
        if (state.completedMessage != null) {
            setFragmentResult(SMB_FILE_OPERATION_RESULT,
                bundleOf(SMB_FILE_OPERATION_MESSAGE to state.completedMessage))
            dismiss()
            return
        }
        isCancelable = !state.busy
        name.isEnabled = !state.busy
        path.text = model.folder?.displayPath.orEmpty()
        status.text = when {
            state.error != null -> getString(state.error)
            state.busy -> getString(R.string.smb_working)
            moving -> getString(R.string.smb_folder_hint)
            else -> ""
        }
        folders.adapter = ArrayAdapter(requireContext(), android.R.layout.simple_list_item_1, state.folders)
        folders.isEnabled = !state.busy && !state.uncertain
        parent.isEnabled = !state.busy && !state.uncertain && model.folder?.segments?.isNotEmpty() == true
        retry.visibility = if (moving && state.error != null && !state.busy && !state.uncertain) View.VISIBLE else View.GONE
        (dialog as? AlertDialog)?.let {
            it.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = !state.busy && !state.uncertain && (!moving || state.folderLoaded)
            it.getButton(AlertDialog.BUTTON_NEGATIVE)?.isEnabled = !state.busy
        }
    }

    companion object {
        fun newInstance(source: String, moving: Boolean) = SmbFileOperationDialog().apply {
            arguments = bundleOf("source" to source, "moving" to moving)
        }
    }
}

data class SmbOperationState(
    val folders: List<String> = emptyList(),
    val folderLoaded: Boolean = false,
    val busy: Boolean = false,
    val error: Int? = null,
    val uncertain: Boolean = false,
    val completedMessage: Int? = null
)

class SmbFileOperationModel(application: Application) : AndroidViewModel(application) {
    val state = MutableLiveData(SmbOperationState())
    internal var folder: SmbPath? = null
        private set
    var name = ""
    private var source: SmbPath? = null
    private var sourceUri = ""
    private var moving = false
    private var initialized = false
    var writing = false
        private set
    private val operations = SmbFileOperations(application)

    fun initialize(uri: String, move: Boolean, interrupted: Boolean) {
        if (initialized) return
        initialized = true
        moving = move
        sourceUri = uri
        source = runCatching { SmbPath.parse(uri).also { require(it.segments.isNotEmpty()) } }.getOrNull()
        val original = source ?: run {
            state.value = SmbOperationState(error = R.string.smb_unsupported, uncertain = true)
            return
        }
        name = original.name
        folder = original.parent
        if (interrupted) state.value = SmbOperationState(error = R.string.smb_operation_uncertain, uncertain = true)
        else if (move) loadFolder(original.parent)
    }

    internal fun loadFolder(target: SmbPath) {
        if (state.value?.busy == true || state.value?.uncertain == true) return
        val previous = state.value ?: SmbOperationState()
        state.value = previous.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                val entries = withContext(Dispatchers.IO) { operations.folders(target) }
                folder = target
                state.value = SmbOperationState(folders = entries, folderLoaded = true)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                state.value = previous.copy(error = smbErrorMessage(e, false), busy = false)
            }
        }
    }

    fun execute() {
        val previous = state.value ?: return
        if (previous.busy || previous.uncertain || (moving && !previous.folderLoaded)) return
        val original = source ?: return
        val destinationFolder = folder ?: return
        val targetName = if (moving) original.name else name
        if (runCatching { SmbPath.validateName(targetName) }.isFailure) {
            state.value = previous.copy(error = R.string.smb_invalid_name)
            return
        }
        val target = runCatching { original.destination(destinationFolder, targetName) }.getOrNull()
        if (target == null) {
            state.value = previous.copy(error = R.string.smb_same_path)
            return
        }
        val playing = PlaylistManager.currentPlayedMedia.value?.uri?.toString()
        if (playing != null && runCatching { SmbPath.parse(playing).sameFile(original) }.getOrDefault(false)) {
            state.value = previous.copy(error = R.string.smb_file_in_use)
            return
        }
        state.value = previous.copy(busy = true, error = null)
        writing = true
        viewModelScope.launch {
            // Once sent, cancellation cannot undo a server-side rename. Finish reconciliation.
            withContext(NonCancellable) {
                try {
                    val progressCopied = withContext(Dispatchers.IO) {
                        val progress = runCatching {
                            Medialibrary.getInstance().getMedia(sourceUri)?.takeIf { it.id > 0 }?.let {
                                PlaybackProgress(it.length, it.time, it.position, it.playCount)
                            }
                        }
                        operations.rename(original, target)
                        runCatching {
                            val targetUri = android.net.Uri.parse(sourceUri).buildUpon().path(target.displayPath).build().toString()
                            val copied = progress.isSuccess && copyProgress(progress.getOrNull(), targetUri)
                            // Reconcile scanned NAS videos with their new paths, including Video tab cards.
                            val library = Medialibrary.getInstance()
                            val parentUri = android.net.Uri.parse(sourceUri).buildUpon()
                                .path(original.parent.displayPath + "/").build().toString()
                            library.reload(parentUri)
                            if (original.parent != target.parent) {
                                library.reload(android.net.Uri.parse(targetUri).buildUpon()
                                    .path(target.parent.displayPath + "/").build().toString())
                            }
                            copied
                        }.getOrDefault(false)
                    }
                    state.value = previous.copy(completedMessage = if (progressCopied)
                        R.string.smb_operation_done else R.string.smb_progress_not_copied)
                } catch (e: Exception) {
                    val message = smbErrorMessage(e, true)
                    state.value = previous.copy(busy = false, error = message,
                        uncertain = message == R.string.smb_operation_uncertain)
                } finally {
                    writing = false
                }
            }
        }
    }

    private data class PlaybackProgress(val length: Long, val time: Long, val position: Float, val playCount: Long)

    private fun copyProgress(old: PlaybackProgress?, targetUri: String): Boolean = try {
        val library = Medialibrary.getInstance()
        if (old == null) true else {
            val updated = library.getMedia(targetUri) ?: library.addMedia(targetUri, old.length)
            updated != null && updated.id > 0 &&
                library.setLastTime(updated.id, old.time.coerceAtLeast(0)) != Medialibrary.ML_SET_TIME_ERROR &&
                library.setLastPosition(updated.id, old.position.coerceIn(0F, 1F)) && updated.setPlayCount(old.playCount)
        }
    } catch (_: Exception) {
        false
    }

}
