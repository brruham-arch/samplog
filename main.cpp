#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define LOGFILE "/storage/emulated/0/samplog_crash.txt"
#define TESTLOG "/storage/emulated/0/samplog_test.txt"
#define EXPORT __attribute__((visibility("default")))
#define MOD_VERSION "v2.6"

static struct sigaction g_old[4];

// ---------- ring buffer kejadian terakhir ----------
static char g_ev[32][112];
static volatile unsigned g_evn = 0;
static void evt(const char* fmt, ...) {
    unsigned i = (g_evn++) % 32;
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_ev[i], sizeof(g_ev[i]), fmt, ap);
    va_end(ap);
}

// ---------- baca memori aman (EFAULT, bukan crash) lewat pipe ----------
static int g_pipe[2] = {-1, -1};
static bool safeRead(const void* src, void* dst, size_t n) {
    if (g_pipe[1] < 0 || n == 0 || n > 256) return false;
    ssize_t w = write(g_pipe[1], src, n);
    if (w <= 0) return false;
    char tmp[256];
    ssize_t r = read(g_pipe[0], tmp, (size_t)w);
    if (w != (ssize_t)n || r != w) return false;
    memcpy(dst, tmp, n);
    return true;
}

// ---------- peta modul ----------
struct Map { uintptr_t s, e; bool x; char p[128]; };
static Map g_maps[700];
static int g_nmaps = 0;

static void loadMaps() {
    g_nmaps = 0;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    while (g_nmaps < 700 && fgets(line, sizeof(line), f)) {
        uintptr_t s, e; char perm[8] = {0}; char path[256] = {0};
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255[^\n]", &s, &e, perm, path) >= 3) {
            Map& m = g_maps[g_nmaps++];
            m.s = s; m.e = e; m.x = (perm[2] == 'x');
            strncpy(m.p, path, sizeof(m.p) - 1); m.p[sizeof(m.p) - 1] = 0;
        }
    }
    fclose(f);
}

// cari modul + offset (offset = addr - alamat mapping terendah modul itu)
static bool symbolize(uintptr_t a, const char** name, uintptr_t* off) {
    for (int i = 0; i < g_nmaps; i++) {
        if (a >= g_maps[i].s && a < g_maps[i].e && g_maps[i].p[0] == '/') {
            uintptr_t base = g_maps[i].s;
            for (int j = 0; j < g_nmaps; j++)
                if (strcmp(g_maps[j].p, g_maps[i].p) == 0 && g_maps[j].s < base) base = g_maps[j].s;
            const char* slash = strrchr(g_maps[i].p, '/');
            *name = slash ? slash + 1 : g_maps[i].p;
            *off = a - base;
            return true;
        }
    }
    return false;
}

static void dumpMem(FILE* f, const char* label, uintptr_t addr, size_t len) {
    unsigned char buf[256];
    if (addr < 0x1000) { fprintf(f, "%s: (bukan pointer)\n", label); return; }
    if (!safeRead((void*)addr, buf, len)) { fprintf(f, "%s [0x%lx]: tidak terbaca\n", label, (unsigned long)addr); return; }
    fprintf(f, "%s [0x%lx] %zu byte:\n", label, (unsigned long)addr, len);
    for (size_t i = 0; i < len; i += 16) {
        fprintf(f, "  +%02zx:", i);
        for (size_t j = i; j < i + 16 && j < len; j++) fprintf(f, " %02x", buf[j]);
        fprintf(f, "\n");
    }
}

static void crashHandler(int sig, siginfo_t* info, void* ucontextRaw) {
    ucontext_t* uc = (ucontext_t*)ucontextRaw;
    loadMaps();
    FILE* f = fopen(LOGFILE, "a");
    if (f) {
        char tname[32] = {0}; prctl(PR_GET_NAME, (unsigned long)tname, 0, 0, 0);
        fprintf(f, "==== CRASH [%s] ====\n", MOD_VERSION);
        fprintf(f, "time: %ld  tid: %ld  thread: %s\n", (long)time(nullptr), (long)syscall(__NR_gettid), tname);
        fprintf(f, "signal: %d code: %d fault_addr: %p\n", sig, info->si_code, info->si_addr);
#if defined(__arm__)
        uintptr_t regs[17] = {
            uc->uc_mcontext.arm_r0, uc->uc_mcontext.arm_r1, uc->uc_mcontext.arm_r2, uc->uc_mcontext.arm_r3,
            uc->uc_mcontext.arm_r4, uc->uc_mcontext.arm_r5, uc->uc_mcontext.arm_r6, uc->uc_mcontext.arm_r7,
            uc->uc_mcontext.arm_r8, uc->uc_mcontext.arm_r9, uc->uc_mcontext.arm_r10, uc->uc_mcontext.arm_fp,
            uc->uc_mcontext.arm_ip, uc->uc_mcontext.arm_sp, uc->uc_mcontext.arm_lr, uc->uc_mcontext.arm_pc,
            uc->uc_mcontext.arm_cpsr };
        const char* rn[17] = {"r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","fp","ip","sp","lr","pc","cpsr"};
        const char* nm; uintptr_t off;
        if (symbolize(regs[15], &nm, &off)) fprintf(f, "pc: 0x%lx module: %s offset: 0x%lx\n", (unsigned long)regs[15], nm, (unsigned long)off);
        else fprintf(f, "pc: 0x%lx module: (tidak ada)\n", (unsigned long)regs[15]);
        fprintf(f, "mode: %s\n", (regs[16] & 0x20) ? "Thumb" : "ARM");
        if (symbolize(regs[14], &nm, &off)) fprintf(f, "lr: 0x%lx module: %s offset: 0x%lx (lr bisa dipakai sbg register biasa)\n", (unsigned long)regs[14], nm, (unsigned long)off);
        fprintf(f, "registers:\n");
        for (int i = 0; i < 17; i++) fprintf(f, "  %-4s 0x%08lx\n", rn[i], (unsigned long)regs[i]);

        // mapping di sekitar fault_addr
        uintptr_t fa = (uintptr_t)info->si_addr;
        bool found = false;
        for (int i = 0; i < g_nmaps; i++) {
            if (fa >= g_maps[i].s && fa < g_maps[i].e) {
                fprintf(f, "fault_addr ada di mapping: %lx-%lx %s\n", (unsigned long)g_maps[i].s, (unsigned long)g_maps[i].e, g_maps[i].p);
                found = true; break;
            }
        }
        if (!found) {
            fprintf(f, "fault_addr TIDAK terpetakan. mapping terdekat sebelumnya:\n");
            int best = -1;
            for (int i = 0; i < g_nmaps; i++) if (g_maps[i].e <= fa && (best < 0 || g_maps[i].e > g_maps[best].e)) best = i;
            if (best >= 0) fprintf(f, "  %lx-%lx %s\n", (unsigned long)g_maps[best].s, (unsigned long)g_maps[best].e, g_maps[best].p);
        }

        // dump memori sekitar register penting
        dumpMem(f, "mem[r0]", regs[0], 0x40);
        dumpMem(f, "mem[r1]", regs[1], 0x20);
        dumpMem(f, "mem[r2]", regs[2], 0x20);
        if (regs[3] >= 0x30) dumpMem(f, "mem[r3-0x30]", regs[3] - 0x30, 0x30);

        // stack scan: nilai di stack yang menunjuk ke kode (tebakan backtrace)
        fprintf(f, "stack scan (kandidat pemanggil, bisa ada sisa lama):\n");
        int shown = 0;
        for (int blk = 0; blk < 4 && shown < 24; blk++) {
            uintptr_t w[64];
            if (!safeRead((void*)(regs[13] + blk * 256), w, 256)) break;
            for (int k = 0; k < 64 && shown < 24; k++) {
                uintptr_t v = w[k] & ~(uintptr_t)1;
                for (int i = 0; i < g_nmaps; i++) {
                    if (g_maps[i].x && g_maps[i].p[0] == '/' && v >= g_maps[i].s && v < g_maps[i].e) {
                        if (symbolize(v, &nm, &off))
                            fprintf(f, "  sp+0x%x: 0x%lx %s+0x%lx\n", blk * 256 + k * 4, (unsigned long)w[k], nm, (unsigned long)off);
                        shown++;
                        break;
                    }
                }
            }
        }
#endif
        // kejadian terakhir sebelum crash
        fprintf(f, "kejadian terakhir:\n");
        for (unsigned k = 0; k < 32; k++) {
            unsigned idx = (g_evn + k) % 32;
            if (g_ev[idx][0]) fprintf(f, "  - %s\n", g_ev[idx]);
        }
        fprintf(f, "\n");
        fclose(f);
    }
    int idx = (sig==SIGSEGV)?0:(sig==SIGABRT)?1:(sig==SIGBUS)?2:3;
    sigaction(sig, &g_old[idx], nullptr);
    raise(sig);
}

static char g_altstack[65536];

static void install(int sig, int idx) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crashHandler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(sig, &sa, &g_old[idx]);
}

typedef void* (*RwStreamOpenFn)(int, int, void*);
typedef void* (*RpClumpGtaStreamReadFn)(void*);

struct ParamsBufFirst { void* buffer; uint32_t length; };
struct ParamsLenFirst { uint32_t length; void* buffer; };

static RwStreamOpenFn g_RwStreamOpen = nullptr;
static RpClumpGtaStreamReadFn g_RpClumpGtaStreamRead = nullptr;

static bool ensureSyms(FILE* log) {
    if (g_RwStreamOpen && g_RpClumpGtaStreamRead) return true;
    void* hGtasa = dlopen("libGTASA.so", RTLD_NOW);
    if (log) fprintf(log, "dlopen libGTASA.so handle=%p\n", hGtasa);
    if (!hGtasa) return false;
    g_RwStreamOpen = (RwStreamOpenFn)dlsym(hGtasa, "_Z12RwStreamOpen12RwStreamType18RwStreamAccessTypePKv");
    g_RpClumpGtaStreamRead = (RpClumpGtaStreamReadFn)dlsym(hGtasa, "_Z20RpClumpGtaStreamReadP8RwStream");
    if (log) fprintf(log, "RwStreamOpen=%p RpClumpGtaStreamRead=%p\n", (void*)g_RwStreamOpen, (void*)g_RpClumpGtaStreamRead);
    return g_RwStreamOpen && g_RpClumpGtaStreamRead;
}

static unsigned char* readWholeFile(const char* path, long* outSize, FILE* log) {
    FILE* f = fopen(path, "rb");
    if (!f) { if (log) fprintf(log, "fopen gagal errno=%d (%s)\n", errno, strerror(errno)); return nullptr; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(size);
    size_t rd = fread(buf, 1, size, f);
    fclose(f);
    if (log) fprintf(log, "fopen sukses size=%ld fread=%zu\n", size, rd);
    *outSize = size;
    return buf;
}

extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "samplog|" MOD_VERSION "|multi-variant clump loader + anim init + detail crash log|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() { remove(LOGFILE); remove(TESTLOG); }

EXPORT void OnModLoad() {
    pipe2(g_pipe, O_NONBLOCK);
    stack_t ss; ss.ss_sp = g_altstack; ss.ss_size = sizeof(g_altstack); ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);
    install(SIGSEGV, 0); install(SIGABRT, 1);
    install(SIGBUS, 2); install(SIGILL, 3);
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "[samplog] ===== MOD LOADED: %s =====\n", MOD_VERSION); fclose(f); }
    evt("mod loaded %s", MOD_VERSION);
}

// Bisa dipanggil dari Lua (ffi) untuk menandai kejadian: samplog_event("ganti skin 5")
EXPORT void samplog_event(const char* s) { evt("%s", s ? s : "(null)"); }

EXPORT int samplog_test_fopen(const char* path) {
    long size = 0;
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "[test_fopen] path=%s\n", path);
    unsigned char* buf = readWholeFile(path, &size, log);
    if (log) fclose(log);
    if (!buf) return -1;
    free(buf);
    return (int)size;
}

// Variant A: type=3, full buffer (termasuk 12-byte header), struct {buffer,length}
EXPORT void* samplog_clump_A(const char* path) {
    evt("clump_A %s", path ? path : "(null)");
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== VARIANT A: type=3 full-buffer {buffer,length} ===\n");
    long size = 0;
    unsigned char* buf = readWholeFile(path, &size, log);
    if (!buf || !ensureSyms(log)) { if (log) fclose(log); return nullptr; }
    ParamsBufFirst params;
    params.buffer = buf;
    params.length = (uint32_t)size;
    void* stream = g_RwStreamOpen(3, 1, &params);
    if (log) fprintf(log, "A: stream=%p\n", stream);
    void* clump = nullptr;
    if (stream) {
        clump = g_RpClumpGtaStreamRead(stream);
        if (log) fprintf(log, "A: clump=%p\n", clump);
    }
    evt("clump_A hasil stream=%p clump=%p", stream, clump);
    if (log) fclose(log);
    return clump;
}

// Variant B: type=3, skip 12-byte header, struct {buffer,length}
EXPORT void* samplog_clump_B(const char* path) {
    evt("clump_B %s", path ? path : "(null)");
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== VARIANT B: type=3 skip-header {buffer,length} ===\n");
    long size = 0;
    unsigned char* buf = readWholeFile(path, &size, log);
    if (!buf || !ensureSyms(log)) { if (log) fclose(log); return nullptr; }
    if (size <= 12) { if (log) { fprintf(log, "B: file kekecilan\n"); fclose(log); } return nullptr; }
    ParamsBufFirst params;
    params.buffer = buf + 12;
    params.length = (uint32_t)(size - 12);
    void* stream = g_RwStreamOpen(3, 1, &params);
    if (log) fprintf(log, "B: stream=%p\n", stream);
    void* clump = nullptr;
    if (stream) {
        clump = g_RpClumpGtaStreamRead(stream);
        if (log) fprintf(log, "B: clump=%p\n", clump);
    }
    evt("clump_B hasil stream=%p clump=%p", stream, clump);
    if (log) fclose(log);
    return clump;
}

// Variant C: type=4, full buffer, struct {buffer,length} (jaga-jaga kalau enum type beda)
EXPORT void* samplog_clump_C(const char* path) {
    evt("clump_C %s", path ? path : "(null)");
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== VARIANT C: type=4 full-buffer {buffer,length} ===\n");
    long size = 0;
    unsigned char* buf = readWholeFile(path, &size, log);
    if (!buf || !ensureSyms(log)) { if (log) fclose(log); return nullptr; }
    ParamsBufFirst params;
    params.buffer = buf;
    params.length = (uint32_t)size;
    void* stream = g_RwStreamOpen(4, 1, &params);
    if (log) fprintf(log, "C: stream=%p\n", stream);
    void* clump = nullptr;
    if (stream) {
        clump = g_RpClumpGtaStreamRead(stream);
        if (log) fprintf(log, "C: clump=%p\n", clump);
    }
    evt("clump_C hasil stream=%p clump=%p", stream, clump);
    if (log) fclose(log);
    return clump;
}

// Variant D: type=3, full buffer, struct DIBALIK {length,buffer}
EXPORT void* samplog_clump_D(const char* path) {
    evt("clump_D %s", path ? path : "(null)");
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== VARIANT D: type=3 full-buffer {length,buffer} DIBALIK ===\n");
    long size = 0;
    unsigned char* buf = readWholeFile(path, &size, log);
    if (!buf || !ensureSyms(log)) { if (log) fclose(log); return nullptr; }
    ParamsLenFirst params;
    params.length = (uint32_t)size;
    params.buffer = buf;
    void* stream = g_RwStreamOpen(3, 1, &params);
    if (log) fprintf(log, "D: stream=%p\n", stream);
    void* clump = nullptr;
    if (stream) {
        clump = g_RpClumpGtaStreamRead(stream);
        if (log) fprintf(log, "D: clump=%p\n", clump);
    }
    evt("clump_D hasil stream=%p clump=%p", stream, clump);
    if (log) fclose(log);
    return clump;
}

// Variant E: type=3, skip header, struct DIBALIK {length,buffer}
EXPORT void* samplog_clump_E(const char* path) {
    evt("clump_E %s", path ? path : "(null)");
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== VARIANT E: type=3 skip-header {length,buffer} DIBALIK ===\n");
    long size = 0;
    unsigned char* buf = readWholeFile(path, &size, log);
    if (!buf || !ensureSyms(log)) { if (log) fclose(log); return nullptr; }
    if (size <= 12) { if (log) { fprintf(log, "E: file kekecilan\n"); fclose(log); } return nullptr; }
    ParamsLenFirst params;
    params.length = (uint32_t)(size - 12);
    params.buffer = buf + 12;
    void* stream = g_RwStreamOpen(3, 1, &params);
    if (log) fprintf(log, "E: stream=%p\n", stream);
    void* clump = nullptr;
    if (stream) {
        clump = g_RpClumpGtaStreamRead(stream);
        if (log) fprintf(log, "E: clump=%p\n", clump);
    }
    evt("clump_E hasil stream=%p clump=%p", stream, clump);
    if (log) fclose(log);
    return clump;
}

// Variant F: type=5, full buffer, struct {buffer,length}
EXPORT void* samplog_clump_F(const char* path) {
    evt("clump_F %s", path ? path : "(null)");
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== VARIANT F: type=5 full-buffer {buffer,length} ===\n");
    long size = 0;
    unsigned char* buf = readWholeFile(path, &size, log);
    if (!buf || !ensureSyms(log)) { if (log) fclose(log); return nullptr; }
    ParamsBufFirst params;
    params.buffer = buf;
    params.length = (uint32_t)size;
    void* stream = g_RwStreamOpen(5, 1, &params);
    if (log) fprintf(log, "F: stream=%p\n", stream);
    void* clump = nullptr;
    if (stream) {
        clump = g_RpClumpGtaStreamRead(stream);
        if (log) fprintf(log, "F: clump=%p\n", clump);
    }
    evt("clump_F hasil stream=%p clump=%p", stream, clump);
    if (log) fclose(log);
    return clump;
}

typedef void* (*GetHierFromClumpFn)(void*);
typedef void (*SetFrameHierFn)(void*, void*);
typedef void (*UpdateMatricesFn)(void*);

EXPORT bool samplog_swap_clump_safe(void* pedPtr, void* newClump) {
    evt("swap ped=%p newClump=%p", pedPtr, newClump);
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== SWAP SAFE [%s] ===\n", MOD_VERSION);
    void* hGtasa = dlopen("libGTASA.so", RTLD_NOW);
    if (!hGtasa) { if (log) { fprintf(log, "dlopen gagal\n"); fclose(log); } return false; }
    static GetHierFromClumpFn GetAnimHierarchyFromClump =
        (GetHierFromClumpFn)dlsym(hGtasa, "_Z25GetAnimHierarchyFromClumpP7RpClump");
    static SetFrameHierFn RpHAnimFrameSetHierarchy =
        (SetFrameHierFn)dlsym(hGtasa, "_Z24RpHAnimFrameSetHierarchyP7RwFrameP16RpHAnimHierarchy");
    static UpdateMatricesFn RpHAnimHierarchyUpdateMatrices =
        (UpdateMatricesFn)dlsym(hGtasa, "_Z30RpHAnimHierarchyUpdateMatricesP16RpHAnimHierarchy");
    if (log) fprintf(log, "syms: %p %p %p\n",
        (void*)GetAnimHierarchyFromClump, (void*)RpHAnimFrameSetHierarchy, (void*)RpHAnimHierarchyUpdateMatrices);
    if (!GetAnimHierarchyFromClump || !RpHAnimFrameSetHierarchy) {
        if (log) fclose(log); return false;
    }
    void** clumpSlot = (void**)((unsigned char*)pedPtr + 0x18);
    void* oldClump = *clumpSlot;
    if (log) fprintf(log, "oldClump=%p newClump=%p\n", oldClump, newClump);
    if (!oldClump || !newClump) { if (log) fclose(log); return false; }
    void* hier = GetAnimHierarchyFromClump(oldClump);
    if (log) fprintf(log, "hier=%p\n", hier);
    if (!hier) { if (log) fclose(log); return false; }

    typedef void (*ClumpInitFn)(void*);
    typedef void (*AddAnimFn)(void*, int, int);
    typedef void* (*GetFirstAssocFnLocal)(void*);
    static ClumpInitFn RpAnimBlendClumpInit =
        (ClumpInitFn)dlsym(hGtasa, "_Z20RpAnimBlendClumpInitP7RpClump");
    static AddAnimFn CAnimManager_AddAnimation =
        (AddAnimFn)dlsym(hGtasa, "_ZN12CAnimManager12AddAnimationEP7RpClump12AssocGroupId11AnimationId");
    static GetFirstAssocFnLocal RpAnimBlendClumpGetFirstAssociation_local =
        (GetFirstAssocFnLocal)dlsym(hGtasa, "_Z35RpAnimBlendClumpGetFirstAssociationP7RpClump");
    if (log) fprintf(log, "clumpInit=%p addAnim=%p\n", (void*)RpAnimBlendClumpInit, (void*)CAnimManager_AddAnimation);

    if (RpAnimBlendClumpInit) {
        RpAnimBlendClumpInit(newClump);
        evt("swap: RpAnimBlendClumpInit selesai");
        if (log) fprintf(log, "RpAnimBlendClumpInit dipanggil\n");
    }
    if (CAnimManager_AddAnimation) {
        CAnimManager_AddAnimation(newClump, 0, 3); // group 0, ANIM_STD_IDLE_STANCE (id umum=3)
        void* checkAssoc = nullptr;
        if (RpAnimBlendClumpGetFirstAssociation_local) {
            checkAssoc = RpAnimBlendClumpGetFirstAssociation_local(newClump);
        }
        evt("swap: AddAnimation selesai assoc=%p", checkAssoc);
        if (log) fprintf(log, "AddAnimation dipanggil, firstAssoc setelah init=%p\n", checkAssoc);
    }

    // RwObject layout: byte type,subType,flags,privateFlags lalu void* parent (frame) di offset 0x4
    void* newFrame = *(void**)((unsigned char*)newClump + 0x4);
    if (log) fprintf(log, "newFrame=%p\n", newFrame);
    if (!newFrame) { if (log) fclose(log); return false; }
    RpHAnimFrameSetHierarchy(newFrame, hier);
    if (RpHAnimHierarchyUpdateMatrices) RpHAnimHierarchyUpdateMatrices(hier);
    *clumpSlot = newClump;
    evt("swap: SELESAI ok");
    if (log) { fprintf(log, "SWAP OK\n"); fclose(log); }
    return true;
}

} // extern "C"
