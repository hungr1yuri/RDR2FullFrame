// finder.exe - the diagnostic tool used to locate the patch on this build.
// Kept in the repo so the search is reproducible, not just the result.
//
// Value-hunt commands (Cheat Engine style, state in finder_state.bin):
//   scan <v> [eps]   fresh scan for float ~= v
//   changed [eps]    keep addrs whose value moved since last step
//   unchanged [eps]  keep addrs whose value held
//   next <v> [eps]   keep addrs whose value is now ~= v
//   list             show survivors (stored -> current)
//   set <v>          write a float to all survivors
//
// Code-patch commands (for the verified letterbox fix):
//   aob <pattern>    scan RDR2.exe module for a byte signature (?? = wildcard),
//                    e.g.  aob C6 05 ?? ?? ?? ?? 01 77 07 40 88 3D ?? ?? ?? ??
//                    prints each match: address, RDR2.exe+offset, 16-byte dump
//   wb <addr> <b..>  write byte(s) at a hex address and read back to verify,
//                    e.g.  wb 7ff7aac50f35 00
//
// State/addresses are valid for one RDR2 session (don't restart mid-hunt).

#include "mem.h"
#include <cstdio>
#include <string>
#include <vector>
#include <cmath>
#include <cstring>
#include <cstdlib>

static const wchar_t* kProc = L"RDR2.exe";

struct Hit { uintptr_t addr; float val; };

// --- Float helpers (value hunting; only the finder uses these) -------------
static bool read_float(HANDLE proc, uintptr_t addr, float& out) {
    SIZE_T got = 0;
    return ReadProcessMemory(proc, (LPCVOID)addr, &out, 4, &got) && got == 4;
}
static bool write_float(HANDLE proc, uintptr_t addr, float val) {
    SIZE_T put = 0;
    return WriteProcessMemory(proc, (LPVOID)addr, &val, 4, &put) && put == 4;
}
// Scan readable, non-mapped regions for 4-byte floats within eps of target.
// Aspect/letterbox floats live in module static data or on the heap, never in
// file-backed mappings (textures/RPF), so skipping those cuts scan time a lot.
static std::vector<uintptr_t> scan_float(HANDLE proc, float target, float eps) {
    std::vector<uintptr_t> hits;
    std::vector<uint8_t> buf;
    for (const auto& r : ff::readable_regions(proc)) {
        if (r.type == MEM_MAPPED) continue;
        if (r.size > (256u << 20)) continue;             // skip huge stream pools
        buf.resize(r.size);
        SIZE_T got = 0;
        if (!ReadProcessMemory(proc, (LPCVOID)r.base, buf.data(), r.size, &got) || got < 4)
            continue;
        for (SIZE_T i = 0; i + 4 <= got; i += 4) {       // aligned struct fields
            float v; std::memcpy(&v, &buf[i], 4);
            if (std::isfinite(v) && std::fabs(v - target) <= eps)
                hits.push_back(r.base + i);
        }
    }
    return hits;
}

static std::wstring state_path() {
    wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring s(p); size_t k = s.find_last_of(L"\\/");
    return (k == std::wstring::npos ? L"." : s.substr(0, k)) + L"\\finder_state.bin";
}
static void save_state(const std::vector<Hit>& a) {
    FILE* f = _wfopen(state_path().c_str(), L"wb");
    if (!f) { printf("! cannot write state\n"); return; }
    uint64_t n = a.size(); fwrite(&n, sizeof(n), 1, f);
    for (auto& h : a) { uint64_t v = h.addr; fwrite(&v, 8, 1, f); fwrite(&h.val, 4, 1, f); }
    fclose(f);
}
static std::vector<Hit> load_state() {
    std::vector<Hit> a;
    FILE* f = _wfopen(state_path().c_str(), L"rb");
    if (!f) return a;
    uint64_t n = 0; if (fread(&n, sizeof(n), 1, f) == 1)
        for (uint64_t i = 0; i < n; ++i) { uint64_t v; float val;
            if (fread(&v,8,1,f)==1 && fread(&val,4,1,f)==1) a.push_back({(uintptr_t)v, val}); }
    fclose(f);
    return a;
}

struct Ctx { HANDLE proc; DWORD pid; uintptr_t base; size_t size; };

static bool attach(Ctx& c) {
    c.pid = ff::find_pid(kProc);
    if (!c.pid) { printf("! RDR2.exe not running\n"); return false; }
    c.proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                         PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, c.pid);
    if (!c.proc) { printf("! OpenProcess failed (err %lu)\n", GetLastError()); return false; }
    c.base = ff::module_base(c.pid, kProc);
    c.size = ff::module_size(c.pid, kProc);
    printf("attached RDR2.exe pid=%lu base=0x%llx size=0x%llx\n",
           c.pid, (unsigned long long)c.base, (unsigned long long)c.size);
    return true;
}
static void where(const Ctx& c, uintptr_t a, char* out, size_t n) {
    if (c.base && a >= c.base && a < c.base + c.size)
        snprintf(out, n, "RDR2.exe+0x%llx", (unsigned long long)(a - c.base));
    else snprintf(out, n, "heap/other");
}
static void print_set(const Ctx& c, const std::vector<Hit>& a, size_t maxshow = 60) {
    printf("  %zu address(es)\n", a.size());
    size_t shown = (a.size() < maxshow) ? a.size() : maxshow;
    for (size_t i = 0; i < shown; ++i) {
        float cur = 0; read_float(c.proc, a[i].addr, cur);
        char w[64]; where(c, a[i].addr, w, sizeof(w));
        printf("    0x%llx  was %.5f  now %.5f  [%s]\n",
               (unsigned long long)a[i].addr, a[i].val, cur, w);
    }
    if (a.size() > shown) printf("    ... (%zu more)\n", a.size() - shown);
}

// --- byte-signature parsing/scanning --------------------------------------
// Join argv[from..] into one space-separated pattern string.
static std::wstring join_args(int argc, wchar_t** argv, int from) {
    std::wstring s;
    for (int i = from; i < argc; ++i) { if (i > from) s += L" "; s += argv[i]; }
    return s;
}
// Parse "C6 05 ?? .. 01" -> bytes + mask ('x' match, '?' wildcard).
static bool parse_pattern(const std::wstring& in, std::vector<uint8_t>& bytes, std::string& mask) {
    size_t i = 0;
    while (i < in.size()) {
        while (i < in.size() && (in[i] == L' ' || in[i] == L'\t')) ++i;
        if (i >= in.size()) break;
        if (in[i] == L'?') {
            bytes.push_back(0); mask.push_back('?');
            while (i < in.size() && in[i] == L'?') ++i;        // accept ? or ??
        } else {
            wchar_t buf[3] = {0,0,0}; int n = 0;
            while (i < in.size() && n < 2 && iswxdigit(in[i])) buf[n++] = in[i++];
            if (n == 0) return false;
            bytes.push_back((uint8_t)wcstoul(buf, nullptr, 16)); mask.push_back('x');
        }
    }
    return !bytes.empty();
}

static void cmd_aob(Ctx& c, const std::wstring& pat) {
    std::vector<uint8_t> bytes; std::string mask;
    if (!parse_pattern(pat, bytes, mask)) { printf("! bad pattern\n"); return; }
    printf("scanning RDR2.exe for %zu-byte signature ...\n", mask.size());
    int found = 0;
    ff::scan_module_regions(c.proc, c.base, c.size,
        [&](uintptr_t rbase, const uint8_t* data, size_t got) {
            size_t off = 0;
            while (off + mask.size() <= got) {
                uintptr_t hit = ff::pattern_scan((uintptr_t)data + off, got - off,
                                                 bytes.data(), mask.c_str());
                if (!hit) break;
                size_t local = (size_t)(hit - (uintptr_t)data);
                uintptr_t remote = rbase + local;
                char w[64]; where(c, remote, w, sizeof(w));
                printf("  MATCH 0x%llx  [%s]\n    bytes:", (unsigned long long)remote, w);
                for (size_t k = 0; k < mask.size() + 4 && local + k < got; ++k)
                    printf(" %02X", data[local + k]);
                printf("\n");
                ++found;
                off = local + 1;
            }
            return false;   // keep scanning every region
        });
    printf("%d match(es)\n", found);
}

static void cmd_wb(Ctx& c, int argc, wchar_t** argv) {
    if (argc < 4) { printf("usage: wb <addr-hex> <byte-hex> [byte-hex ...]\n"); return; }
    uintptr_t addr = (uintptr_t)wcstoull(argv[2], nullptr, 16);
    std::vector<uint8_t> bytes;
    for (int i = 3; i < argc; ++i) bytes.push_back((uint8_t)wcstoul(argv[i], nullptr, 16));
    uint8_t before[16] = {0}; SIZE_T got = 0;
    ReadProcessMemory(c.proc, (LPCVOID)addr, before, bytes.size(), &got);
    SIZE_T put = 0;
    BOOL ok = WriteProcessMemory(c.proc, (LPVOID)addr, bytes.data(), bytes.size(), &put);
    uint8_t after[16] = {0};
    ReadProcessMemory(c.proc, (LPCVOID)addr, after, bytes.size(), &got);
    printf("addr 0x%llx  write %s (%zu/%llu bytes)\n", (unsigned long long)addr,
           ok ? "ok" : "FAILED", bytes.size(), (unsigned long long)put);
    printf("  before:"); for (size_t k=0;k<bytes.size();++k) printf(" %02X", before[k]);
    printf("\n  after :"); for (size_t k=0;k<bytes.size();++k) printf(" %02X", after[k]);
    printf("\n");
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        printf("usage: finder <scan|changed|unchanged|next|list|set|aob|wb> [args]\n");
        return 1;
    }
    std::wstring cmd = argv[1];
    Ctx c{};
    if (!attach(c)) return 2;

    if (cmd == L"aob") {
        cmd_aob(c, join_args(argc, argv, 2));
        CloseHandle(c.proc); return 0;
    }
    if (cmd == L"wb") {
        cmd_wb(c, argc, argv);
        CloseHandle(c.proc); return 0;
    }

    float val = (argc >= 3) ? (float)_wtof(argv[2]) : 0.0f;
    float eps = (argc >= 4) ? (float)_wtof(argv[3]) : 0.0f;

    if (cmd == L"scan") {
        if (eps == 0.0f) eps = 0.01f;
        printf("scan float ~= %.5f (eps %.4f) ...\n", val, eps);
        auto raw = scan_float(c.proc, val, eps);
        std::vector<Hit> hits;
        for (auto a : raw) { float v=0; read_float(c.proc,a,v); hits.push_back({a,v}); }
        save_state(hits); print_set(c, hits);
    } else if (cmd == L"changed" || cmd == L"unchanged") {
        if (eps == 0.0f) eps = 0.001f;
        bool want_changed = (cmd == L"changed");
        auto prev = load_state();
        std::vector<Hit> keep;
        for (auto& h : prev) {
            float cur; if (!read_float(c.proc, h.addr, cur)) continue;
            bool moved = std::fabs(cur - h.val) > eps;
            if (moved == want_changed) keep.push_back({h.addr, cur});
        }
        printf("%ls (eps %.4f): %zu -> %zu\n", cmd.c_str(), eps, prev.size(), keep.size());
        save_state(keep); print_set(c, keep);
    } else if (cmd == L"next") {
        if (eps == 0.0f) eps = 0.002f;
        auto prev = load_state();
        std::vector<Hit> keep;
        for (auto& h : prev) {
            float cur; if (!read_float(c.proc, h.addr, cur)) continue;
            if (std::fabs(cur - val) <= eps) keep.push_back({h.addr, cur});
        }
        printf("next ~= %.5f (eps %.4f): %zu -> %zu\n", val, eps, prev.size(), keep.size());
        save_state(keep); print_set(c, keep);
    } else if (cmd == L"list") {
        print_set(c, load_state());
    } else if (cmd == L"set") {
        auto a = load_state(); size_t ok = 0;
        for (auto& h : a) if (write_float(c.proc, h.addr, val)) ok++;
        printf("wrote %.5f to %zu/%zu addresses\n", val, ok, a.size());
    } else printf("unknown command '%ls'\n", cmd.c_str());

    CloseHandle(c.proc);
    return 0;
}
