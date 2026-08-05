package org.lsposed.lspatch.loader;

import android.util.Log;

import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * NesecCompat — nesec (网易盾) anti-tamper bypass for Android 9-17.
 *
 * Problem:
 *   nesec's libnesec.so decrypts detection code at runtime which calls
 *   exit_group(28) via inline syscall. This cannot be intercepted by
 *   Java hooks or libc patches.
 *
 * Solution:
 *   Hook nesec's Java-layer wrapper methods (MyJni.*) to skip native
 *   detection entirely. The hooks are installed BEFORE nesec's
 *   attachBaseContext runs, ensuring detection is bypassed.
 *
 * Compatibility: Android 9 (SDK 28) through Android 17 (SDK 36).
 */
public class NesecCompat {

    private static final String TAG = "LSPatch";

    // Native method implemented in patch_main.cpp — patches libnesec.so exit SVCs.
    // seccomp is installed in JNI_OnLoad (before this class loads).
    public static native void nativeBlockExit();

    public static void install(ClassLoader classLoader) {
        try {
            installAntiExit();
            installMyJniHooks(classLoader);
            installNesecDialogHooks(classLoader);
            installThreadBlock();
            // Install native exit_group block after MyJni.load completes
            // (libnesec.so is loaded, detection code is in memory)
            Log.i(TAG, "NesecCompat installed");
        } catch (Throwable t) {
            Log.e(TAG, "NesecCompat install failed", t);
        }
    }

    private static void installAntiExit() {
        try {
            XposedBridge.hookMethod(
                Runtime.class.getDeclaredMethod("exit", int.class),
                XC_MethodReplacement.DO_NOTHING);
        } catch (Throwable ignored) {}
        try {
            XposedBridge.hookMethod(
                System.class.getDeclaredMethod("exit", int.class),
                XC_MethodReplacement.DO_NOTHING);
        } catch (Throwable ignored) {}
        try {
            XposedBridge.hookMethod(
                android.os.Process.class.getDeclaredMethod("killProcess", int.class),
                XC_MethodReplacement.DO_NOTHING);
        } catch (Throwable ignored) {}
    }

    private static void installMyJniHooks(ClassLoader cl) {
        Class<?> myJni;
        try {
            myJni = XposedHelpers.findClass(
                "com.netease.nis.wrapper.MyJni", cl);
        } catch (Throwable t) {
            return;
        }

        for (Method m : myJni.getDeclaredMethods()) {
            String name = m.getName();
            Class<?> rt = m.getReturnType();
            Class<?>[] params = m.getParameterTypes();

            // Hook MyJni.load — after libnesec.so loads, install native exit block
            if ("load".equals(name)) {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            Log.i(TAG, "MyJni.load returned " + param.getResult()
                                + " — installing native exit block");
                            nativeBlockExit();
                            Log.i(TAG, "native exit block installed");
                        } catch (Throwable t) {
                            Log.e(TAG, "native exit block failed", t);
                        }
                    }
                });
                continue;
            }

            if (("run".equals(name) || "ra".equals(name) || "rp".equals(name))
                    && rt == boolean.class && params.length == 2
                    && android.app.Application.class.isAssignableFrom(params[1])) {
                hookRunMethod(m);
            } else if ("cp".equals(name) || "ip".equals(name) || "iha".equals(name)) {
                XposedBridge.hookMethod(m, XC_MethodReplacement.DO_NOTHING);
            } else if ("id".equals(name) && rt == boolean.class) {
                XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(true));
            } else if (rt == boolean.class && params.length == 0 && name.length() <= 3) {
                XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(true));
            }
        }
    }

    private static void hookRunMethod(final Method m) {
        XposedBridge.hookMethod(m, new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) {
                try {
                    android.content.Context ctx =
                        (android.content.Context) param.args[0];
                    android.app.Application app =
                        (android.app.Application) param.args[1];
                    if (app != null && app.getBaseContext() == null) {
                        Method attach = android.content.ContextWrapper.class
                            .getDeclaredMethod("attachBaseContext",
                                android.content.Context.class);
                        attach.setAccessible(true);
                        attach.invoke(app, ctx);
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "NesecCompat manual attach failed", t);
                }
                return true;
            }
        });
    }

    private static void installNesecDialogHooks(ClassLoader cl) {
        try {
            Class<?> neDialog = XposedHelpers.findClass(
                "com.netease.nis.wrapper.NEDialog", cl);
            for (Method m : neDialog.getDeclaredMethods()) {
                String name = m.getName();
                if (name.equals("showRiskMessage") || name.contains("exit") || name.contains("Exit")) {
                    XposedBridge.hookMethod(m, XC_MethodReplacement.DO_NOTHING);
                }
            }
        } catch (Throwable ignored) {}
    }

    private static void installThreadBlock() {
        try {
            XposedBridge.hookMethod(
                Thread.class.getDeclaredMethod("start"),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Thread t = (Thread) param.thisObject;
                        String name = t.getName();
                        if (name != null && (name.contains("nesec")
                                || name.contains("NISEC")
                                || name.contains("crashsdk"))) {
                            param.setResult(null);
                        }
                    }
                });
        } catch (Throwable ignored) {}
    }
}
