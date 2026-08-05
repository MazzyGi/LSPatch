/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

//
// Created by Nullptr on 2022/3/17.
//

#include <jni.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <android/log.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "config_impl.h"
#include "patch_loader.h"

#define TAG "LSPatch"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// BPF filter: ERRNO on exit_group(94) and exit(93), ALLOW everything else.
// This makes nesec's inline exit_group syscall fail without killing the process.
static struct sock_filter bpf_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 94, 2, 0), // exit_group
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 93, 1, 0), // exit
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA)),
};

static struct sock_fprog bpf_prog = {
    sizeof(bpf_filter) / sizeof(bpf_filter[0]),
    bpf_filter,
};

// Patch libnesec.so: scan RX memory for exit_group SVC and replace with NOP.
// libnesec decrypts detection code at runtime into its RX segment.
// We scan after MyJni.load returns (libnesec is fully loaded).
static void patch_libnesec_exit() {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return;

    char buf[256 * 1024];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    buf[total] = 0;

    // Find libnesec.so RX segments
    char* line = buf;
    while (*line) {
        char* eol = strchr(line, '\n');
        if (!eol) break;
        *eol = 0;

        // Parse start-end
    unsigned long start = 0;
    unsigned long end = 0;
        char* dash = strchr(line, '-');
        if (!dash) { *eol = '\n'; line = eol + 1; continue; }

        for (char* p = line; p < dash; p++) {
            unsigned long v = 0;
            if (*p >= '0' && *p <= '9') v = *p - '0';
            else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
            else break;
            start = (start << 4) | v;
        }
        for (char* p = dash + 1; *p && *p != ' '; p++) {
            unsigned long v = 0;
            if (*p >= '0' && *p <= '9') v = *p - '0';
            else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
            else break;
            end = (end << 4) | v;
        }

        // Check if this is a libnesec RX segment
        if (strstr(line, "libnesec") && strstr(line, "r-xp")) {
            size_t size = end - start;
            if (size > 0 && size < 4 * 1024 * 1024) {
                // Make it RWX
                void* addr = (void*)start;
                size_t page_start = start & ~0xFFFUL;
                size_t page_end = (end + 0xFFF) & ~0xFFFUL;
                mprotect((void*)page_start, page_end - page_start, PROT_READ | PROT_WRITE | PROT_EXEC);

                // Scan for exit_group SVC pattern:
                // mov x8, #0x5e (94=exit_group) followed by svc #0
                // On arm64: svc #0 = 0xD4000001
                // mov x8, #imm can be: movz x8, #imm (0xD2800008 | (imm << 5))
                // For exit_group(94): 0xD2800BC8 = movz x8, #0x5e
                uint32_t* code = (uint32_t*)addr;
                size_t count = size / 4;
                int patched = 0;
                for (size_t i = 0; i + 1 < count; i++) {
                    // Check for svc #0 (0xD4000001)
                    if (code[i] == 0xD4000001) {
                        // Check if previous instruction sets x8 to 93 or 94
                        // Look back up to 4 instructions for mov x8, #94
                        for (int j = 1; j <= 4 && i >= (size_t)j; j++) {
                            uint32_t prev = code[i - j];
                            // movz x8, #imm16 = 0xD2800008 | (imm16 << 5)
                            if ((prev & 0xFFE0001F) == 0xD2800008) {
                                uint16_t imm = (prev >> 5) & 0xFFFF;
                                if (imm == 93 || imm == 94) {
                                    // NOP the svc instruction
                                    code[i] = 0xD503201F; // NOP
                                    patched++;
                                    LOGI("patched exit SVC at offset 0x%lx (x8=%u)", (unsigned long)(i * 4), imm);
                                    break;
                                }
                            }
                        }
                    }
                }

                // Restore RX
                mprotect((void*)page_start, page_end - page_start, PROT_READ | PROT_EXEC);

                // Flush icache
                for (size_t i = 0; i < size; i += 32) {
                    __builtin___clear_cache((char*)addr + i, (char*)addr + i + 32);
                }

                if (patched > 0) {
                    LOGI("patched %d exit SVCs in libnesec.so segment 0x%lx-0x%lx", patched, start, end);
                }
            }
        }

        *eol = '\n';
        line = eol + 1;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_org_lsposed_lspatch_loader_NesecCompat_nativeBlockExit(JNIEnv*, jclass) {
    // Install seccomp BPF filter to block exit_group/exit syscalls
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        LOGE("prctl PR_SET_NO_NEW_PRIVS failed");
        return;
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &bpf_prog) < 0) {
        LOGE("seccomp install failed");
    } else {
        LOGI("seccomp exit_block installed");
    }

    // Also patch libnesec.so exit SVCs directly
    patch_libnesec_exit();
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    lspd::PatchLoader::Init();
    lspd::ConfigImpl::Init();
    lspd::PatchLoader::GetInstance()->Load(env);
    return JNI_VERSION_1_6;
}
