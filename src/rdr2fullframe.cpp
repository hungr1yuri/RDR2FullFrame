// RDR2FullFrame - removes RDR2 cutscene/cinematic black bars on ultrawide.
//
// RDR2's loader pulls dinput8/version from System32, so a proxy DLL dropped in
// the game folder never loads. The fix is a single code patch though, not a
// per-frame value, so patching the running process from the outside works fine
// and sticks for the whole session.
//
// What this does:
//   1. wait for RDR2.exe
//   2. find the instruction that turns the letterbox flag on
//      (signature confirmed on v1.0.1491.50):
//          mov byte ptr [letterbox_flag], 01
//   3. change the 01 to 00 so the bars never get drawn
//   4. re-check every couple seconds in case the game restores it
//   5. when the game closes, wait for the next launch
//
// Run it before or after launching the game and leave the window open.
// Story mode only.

#include "mem.h"
#include <cstdio>
#include <string>
#include <cstdlib>

static const wchar_t* kProc = L"RDR2.exe";

// C6 05 ?? ?? ?? ?? 01 77 07 40 88 3D ?? ?? ?? ??   (the 01 sits at offset 6)
static const uint8_t  SIG[]  = {0xC6,0x05,0,0,0,0, 0x01, 0x77,0x07,0x40, 0x88,0x3D,0,0,0,0};
static const char     MASK[] = "xx????" "x" "xxx" "xx????";
static const size_t   IMM_OFFSET = 6;

// logging goes next to the exe, so run from a writable folder
static std::wstring exe_dir() {
    wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring s(p); size_t k = s.find_last_of(L"\\/");
    return (k == std::wstring::npos) ? L"." : s.substr(0, k);
}
static bool g_log = true;
static void logmsg(const char* fmt, ...) {
    SYSTEMTIME t; GetLocalTime(&t);
    char line[1024];
    va_list a; va_start(a, fmt); vsnprintf(line, sizeof(line), fmt, a); va_end(a);
    printf("[%02d:%02d:%02d] %s\n", t.wHour, t.wMinute, t.wSecond, line);
    fflush(stdout);
    if (!g_log) return;
    FILE* f = _wfopen((exe_dir() + L"\\rdr2fullframe.log").c_str(), L"a");
    if (f) { fprintf(f, "[%02d:%02d:%02d] %s\n", t.wHour, t.wMinute, t.wSecond, line); fclose(f); }
}

// small ini reader (key = value, ; comments)
static std::string read_file(const std::wstring& path) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) return {};
    std::string s; char b[4096]; size_t n;
    while ((n = fread(b,1,sizeof(b),f)) > 0) s.append(b,n);
    fclose(f); return s;
}
static std::string ini_get(const std::string& ini, const char* key, const char* def) {
    std::string k(key); for (auto& c : k) c = (char)tolower((unsigned char)c);
    size_t pos = 0;
    while (pos < ini.size()) {
        size_t eol = ini.find('\n', pos);
        std::string line = ini.substr(pos, eol==std::string::npos?std::string::npos:eol-pos);
        pos = (eol==std::string::npos)?ini.size():eol+1;
        size_t semi = line.find(';'); if (semi!=std::string::npos) line = line.substr(0,semi);
        size_t eq = line.find('='); if (eq==std::string::npos) continue;
        std::string lk = line.substr(0,eq), lv = line.substr(eq+1);
        auto trim=[](std::string& t){size_t a=t.find_first_not_of(" \t\r\n");size_t b=t.find_last_not_of(" \t\r\n");t=(a==std::string::npos)?std::string():t.substr(a,b-a+1);};
        trim(lk); trim(lv); for (auto& c : lk) c=(char)tolower((unsigned char)c);
        if (lk==k) return lv;
    }
    return def;
}

// Scan the module for the flag instruction. This is the only expensive step,
// so we run it just once per session (until it's found), not on every tick.
// Returns the address of the flag byte, or 0 if not found yet.
static uintptr_t find_flag(HANDLE proc, uintptr_t base, size_t size) {
    uintptr_t hit = ff::scan_module_remote(proc, base, size, SIG, MASK);
    if (!hit) return 0;                          // code not loaded/decrypted yet
    uintptr_t imm = hit + IMM_OFFSET;
    uint8_t cur = 0xFF;
    if (!ff::read_bytes(proc, imm, &cur, 1)) return 0;
    if (cur != 0x00 && cur != 0x01) {
        logmsg("signature at RDR2.exe+0x%llx but flag byte = 0x%02X, ignoring",
               (unsigned long long)(hit - base), cur);
        return 0;
    }
    logmsg("found letterbox flag at RDR2.exe+0x%llx", (unsigned long long)(hit - base));
    return imm;
}

// Cheap: read one byte, write 0 only if the game turned the bars back on.
static void keep_off(HANDLE proc, uintptr_t imm) {
    uint8_t cur = 0xFF;
    if (ff::read_bytes(proc, imm, &cur, 1) && cur != 0x00) {
        uint8_t zero = 0x00;
        if (ff::write_bytes(proc, imm, &zero, 1)) logmsg("bars off");
    }
}

int wmain() {
    std::string ini = read_file(exe_dir() + L"\\RDR2FullFrame.ini");
    g_log = ini_get(ini, "Log", "1") != "0";
    bool removeBars = ini_get(ini, "RemoveCinematicBars", "1") != "0";

    logmsg("RDR2FullFrame started. RemoveCinematicBars=%d", removeBars ? 1 : 0);
    if (!removeBars) logmsg("disabled in RDR2FullFrame.ini, idling");

    for (;;) {                                   // one pass per game session
        DWORD pid = ff::find_pid(kProc);
        if (!pid) { Sleep(2000); continue; }

        HANDLE proc = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                  PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if (!proc) { logmsg("OpenProcess failed (err %lu), retrying", GetLastError()); Sleep(2000); continue; }

        uintptr_t base = ff::module_base(pid, kProc);
        size_t    size = ff::module_size(pid, kProc);
        logmsg("RDR2 found (pid %lu), looking for the flag", pid);

        uintptr_t imm = 0;                         // flag address once located
        for (;;) {
            if (WaitForSingleObject(proc, 0) == WAIT_OBJECT_0) {   // process exited
                logmsg("RDR2 closed, waiting for next launch");
                break;
            }
            if (removeBars) {
                if (!imm) imm = find_flag(proc, base, size);  // scan only until found
                if (imm) keep_off(proc, imm);                 // then just one byte
            }
            // Poll quickly while still searching, then relax to almost nothing.
            Sleep(imm ? 5000 : 1000);
        }
        CloseHandle(proc);
    }
    return 0;
}
