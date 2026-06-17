// Memory helpers shared by RDR2FullFrame.exe and finder.exe.
// Plain Win32 (windows.h, tlhelp32.h), no external libraries.
#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace ff {

// --- Process / module helpers ----------------------------------------------
DWORD     find_pid(const wchar_t* exe_name);          // 0 if not found
uintptr_t module_base(DWORD pid, const wchar_t* mod); // base addr of a module in a remote process
size_t    module_size(DWORD pid, const wchar_t* mod);

// --- External memory access ------------------------------------------------
struct Region { uintptr_t base; size_t size; DWORD protect; DWORD type; };
std::vector<Region> readable_regions(HANDLE proc);    // committed + readable

bool read_bytes(HANDLE proc, uintptr_t addr, void* out, size_t n);
bool write_bytes(HANDLE proc, uintptr_t addr, const void* in, size_t n);

// --- Byte-signature scanning -----------------------------------------------
// mask is 'x' (must match) or '?' (wildcard). pattern_scan works on a local
// buffer. scan_module_regions reads each readable region inside the module
// range [base, base+size) and hands it to fn (region base, bytes, length);
// return true from fn to stop early. scan_module_remote builds on it to return
// the first signature match in the module, or 0.
uintptr_t pattern_scan(uintptr_t start, size_t size,
                       const uint8_t* pattern, const char* mask);
void scan_module_regions(HANDLE proc, uintptr_t base, size_t size,
                         const std::function<bool(uintptr_t, const uint8_t*, size_t)>& fn);
uintptr_t scan_module_remote(HANDLE proc, uintptr_t base, size_t size,
                             const uint8_t* pattern, const char* mask);

} // namespace ff
