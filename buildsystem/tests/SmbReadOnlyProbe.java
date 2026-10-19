/* Temporary instrumentation runner: uses the installed app's saved login, lists one
 * source parent, and reports only a count/status. It never calls rename or move. */
package org.videolan.vlc.smbprobe;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.lang.reflect.InvocationTargetException;
import java.util.List;

public final class SmbReadOnlyProbe extends Instrumentation {
    private String source;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        source = arguments.getString("source");
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            Context context = getTargetContext();
            ClassLoader loader = context.getClassLoader();
            Class<?> pathClass = loader.loadClass("org.videolan.vlc.util.smb.SmbPath");
            Object companion = pathClass.getField("Companion").get(null);
            Object path = companion.getClass().getMethod("parse", String.class).invoke(companion, source);
            Object parent = pathClass.getMethod("getParent").invoke(path);
            Class<?> operationsClass = loader.loadClass("org.videolan.vlc.util.smb.SmbFileOperations");
            Object operations = operationsClass.getConstructor(Context.class).newInstance(context);
            List<?> folders = (List<?>) operationsClass.getMethod("folders", pathClass).invoke(operations, parent);
            result.putString("result", "PASS saved-login parent directory read; folder count=" + folders.size());
            finish(Activity.RESULT_OK, result);
        } catch (Exception error) {
            Throwable cause = error;
            while (cause instanceof InvocationTargetException && cause.getCause() != null) cause = cause.getCause();
            StringBuilder chain = new StringBuilder();
            for (Throwable item = cause; item != null; item = item.getCause()) {
                if (chain.length() != 0) chain.append(" -> ");
                chain.append(item.getClass().getSimpleName());
                String message = item.getMessage();
                if (message != null) for (String keyword : new String[] {
                        "signature", "signing", "timed out", "timeout", "closed", "unreachable",
                        "algorithm", "provider", "encrypt", "decrypt", "STATUS_" }) {
                    if (message.toLowerCase(java.util.Locale.ROOT).contains(keyword.toLowerCase(java.util.Locale.ROOT)))
                        chain.append('[').append(keyword).append(']');
                }
            }
            result.putString("result", "FAIL " + chain);
            try {
                Object status = cause.getClass().getMethod("getStatusCode").invoke(cause);
                result.putString("status", String.valueOf(status));
            } catch (Exception ignored) { }
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
