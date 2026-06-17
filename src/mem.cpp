#include "mem.h"
#include <tlhelp32.h>
#include <cstring>

namespace ff {

// ---------------------------------------------------------------------------
// Process / module discovery
// ---------------------------------------------------------------------------
DWORD find_pid(const wchar_t* exe_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static MODULEENTRY32W find_module_entry(DWORD pid, const wchar_t* mod, bool& ok) {
    ok = false;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return me;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, mod) == 0) { ok = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return me;
}

uintptr_t module_base(DWORD pid, const wchar_t* mod) {
    bool ok; auto me = find_module_entry(pid, mod, ok);
    return ok ? (uintptr_t)me.modBaseAddr : 0;
}
size_t module_size(DWORD pid, const wchar_t* mod) {
    bool ok; auto me = find_module_entry(pid, mod, ok);
    return ok ? (size_t)me.modBaseSize : 0;
}

// ---------------------------------------------------------------------------
// External memory access
// ---------------------------------------------------------------------------
std::vector<Region> readable_regions(HANDLE proc) {
    std::vector<Region> out;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    // 64-bit user space tops out well below this; stop when query fails.
    while (VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        bool committed = (mbi.State == MEM_COMMIT);
        bool readable  = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        bool blocked   = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
        if (committed && readable && !blocked)
            out.push_back({ (uintptr_t)mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type });
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.RegionSize == 0) break;
    }
    return out;
}

bool read_bytes(HANDLE proc, uintptr_t addr, void* out, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(proc, (LPCVOID)addr, out, n, &got) && got == n;
}
bool write_bytes(HANDLE proc, uintptr_t addr, const void* in, size_t n) {
    // Make the page writable, write, restore. (Remote: VirtualProtectEx.)
    DWORD old;
    if (!VirtualProtectEx(proc, (LPVOID)addr, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    SIZE_T put = 0;
    BOOL ok = WriteProcessMemory(proc, (LPVOID)addr, in, n, &put);
    VirtualProtectEx(proc, (LPVOID)addr, n, old, &old);
    return ok && put == n;
}

// ---------------------------------------------------------------------------
// Byte-signature scanning
// ---------------------------------------------------------------------------
void scan_module_regions(HANDLE proc, uintptr_t base, size_t size,
                         const std::function<bool(uintptr_t, const uint8_t*, size_t)>& fn) {
    std::vector<uint8_t> buf;
    for (const auto& r : readable_regions(proc)) {
        if (r.base < base || r.base >= base + size) continue;   // module range only
        buf.resize(r.size);
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)r.base, buf.data(), r.size, &got)) continue;
        if (fn(r.base, buf.data(), (size_t)got)) return;
    }
}

uintptr_t scan_module_remote(HANDLE proc, uintptr_t base, size_t size,
                             const uint8_t* pattern, const char* mask) {
    uintptr_t hit = 0;
    scan_module_regions(proc, base, size,
        [&](uintptr_t rbase, const uint8_t* data, size_t n) {
            uintptr_t local = pattern_scan((uintptr_t)data, n, pattern, mask);
            if (local) { hit = rbase + (local - (uintptr_t)data); return true; }
            return false;
        });
    return hit;
}

uintptr_t pattern_scan(uintptr_t start, size_t size,
                       const uint8_t* pattern, const char* mask) {
    size_t plen = std::strlen(mask);
    if (plen == 0 || size < plen) return 0;
    const uint8_t* base = (const uint8_t*)start;
    for (size_t i = 0; i + plen <= size; ++i) {
        bool ok = true;
        for (size_t j = 0; j < plen; ++j) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) { ok = false; break; }
        }
        if (ok) return start + i;
    }
    return 0;
}

} // namespace ff
