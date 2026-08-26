/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

import java.io.File;

/**
 * Checks that a Linux {@code libnetty_tcnative.so} built against glibc can be loaded and
 * initialized by the libc of the machine running this class. Written for Alpine/musl, with a
 * glibc run as the control.
 *
 * <p>Deliberately depends on nothing but the JDK and {@code netty-tcnative-classes}:
 * netty-tcnative has no dependency on netty-handler, so {@code OpenSsl.isAvailable()} is not
 * available here and the raw {@code io.netty.internal.tcnative} API is the whole surface.
 *
 * <p>One level per JVM, chosen by the first argument, so that a hard crash in an early level
 * cannot hide a later one. On aarch64 the historical failure was a SIGSEGV inside
 * {@code JVM_LoadLibrary} rather than an exception, so the caller must also treat a JVM that
 * dies without printing a RESULT line as a failure -- see verify.sh.
 *
 * <p>Compiled with a modern javac but kept to Java 8 syntax to match the rest of the project.
 */
public final class MuslLoadCheck {

    private static boolean failed;

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: MuslLoadCheck <load|init|context> <path-to-.so>");
            System.exit(2);
        }
        String level = args[0];
        String soPath = args[1];

        try {
            // Every level needs the library loaded; the load itself is level "load".
            load(soPath);
            if (!"load".equals(level)) {
                init();
                if ("context".equals(level)) {
                    context();
                }
            }
        } catch (Throwable t) {
            // A missing symbol surfaces here as the musl loader's own text, e.g.
            // "Error relocating <lib>: __getauxval: symbol not found".
            result(level, false, rootMessage(t));
        }
        System.exit(failed ? 1 : 0);
    }

    private static void load(String soPath) {
        File so = new File(soPath);
        if (!so.isFile()) {
            throw new IllegalStateException("not a file: " + soPath);
        }
        System.load(so.getAbsolutePath());
        result("load", true, "System.load ok: " + so.getName());
    }

    private static void init() throws Exception {
        // Library.initialize() delegates to initialize("provided", null), which loads nothing
        // further and then runs initialize0() and SSL.initialize(). This is where APR and
        // BoringSSL actually start up, and it is the step boringssl-static's own NativeTest
        // never reaches.
        if (!io.netty.internal.tcnative.Library.initialize()) {
            throw new IllegalStateException("Library.initialize() returned false");
        }
        result("init", true, "ssl=" + io.netty.internal.tcnative.SSL.versionString());
    }

    private static void context() throws Exception {
        // Construct and free a real SSL context and a memory BIO. Cheap, but it is the first
        // thing that exercises BoringSSL beyond its own initialization.
        long ctx = io.netty.internal.tcnative.SSLContext.make(
                io.netty.internal.tcnative.SSL.SSL_PROTOCOL_ALL,
                io.netty.internal.tcnative.SSL.SSL_MODE_SERVER);
        if (ctx == 0L) {
            throw new IllegalStateException("SSLContext.make returned 0");
        }
        long bio = 0L;
        try {
            bio = io.netty.internal.tcnative.SSL.newMemBIO();
            if (bio == 0L) {
                throw new IllegalStateException("SSL.newMemBIO returned 0");
            }
            result("context", true, "SSLContext and memory BIO constructed");
        } finally {
            if (bio != 0L) {
                io.netty.internal.tcnative.SSL.freeBIO(bio);
            }
            io.netty.internal.tcnative.SSLContext.free(ctx);
        }
    }

    private static void result(String level, boolean pass, String detail) {
        if (!pass) {
            failed = true;
        }
        System.out.println("RESULT\t" + level + '\t' + (pass ? "PASS" : "FAIL") + '\t' + detail);
    }

    /**
     * Walks to the deepest cause and flattens it onto one line. Note Library tries each entry in
     * its NAMES list and accumulates a message per attempt, so the same musl relocation error can
     * appear twice in one UnsatisfiedLinkError -- that is one failure, not two.
     */
    private static String rootMessage(Throwable t) {
        Throwable root = t;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String msg = root.getMessage();
        if (msg == null || msg.isEmpty()) {
            msg = root.toString();
        }
        return root.getClass().getSimpleName() + ": " + msg.replace('\n', ' ').replace('\r', ' ');
    }

    private MuslLoadCheck() {
    }
}
