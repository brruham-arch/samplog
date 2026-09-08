#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <dlfcn.h>

#define LOGFILE "/storage/emulated/0/samplog_crash.txt"
#define TESTLOG "/storage/emulated/0/samplog_test.txt"
#define EXPORT __attribute__((visibility("default")))

static struct sigaction g_old[4];

static void findModule(uintptr_t addr, char* outName, size_t outLen, uintptr_t* outBase) {
    FILE* f = fopen("/proc/self/maps", "r");
    outName[0] = 0; *outBase = 0;
    if (!f) return;
    char line[512], matched[256] = {0};
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end; char path[256] = {0};
        if (sscanf(line, "%lx-%lx %*s %*x %*x:%*x %*d %255[^\n]", &start, &end, path) >= 2) {
            if (addr >= start && addr < end && path[0] == '/') {
                strncpy(matched, path, sizeof(matched)-1);
                break;
            }
        }
    }
    if (!matched[0]) { fclose(f); return; }
    strncpy(outName, matched, outLen-1);
    rewind(f);
    uintptr_t minStart = (uintptr_t)-1;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end; char path[256] = {0};
        if (sscanf(line, "%lx-%lx %*s %*x %*x:%*x %*d %255[^\n]", &start, &end, path) >= 2) {
            if (strcmp(path, matched) == 0 && start < minStart) minStart = start;
        }
    }
    fclose(f);
    *outBase = (minStart == (uintptr_t)-1) ? 0 : minStart;
}

static void crashHandler(int sig, siginfo_t* info, void* ucontextRaw) {
    ucontext_t* uc = (ucontext_t*)ucontextRaw;
#if defined(__arm__)
    uintptr_t pc = uc->uc_mcontext.arm_pc;
    uintptr_t lr = uc->uc_mcontext.arm_lr;
    uintptr_t r0 = uc->uc_mcontext.arm_r0;
    uintptr_t r1 = uc->uc_mcontext.arm_r1;
    uintptr_t r2 = uc->uc_mcontext.arm_r2;
    uintptr_t r3 = uc->uc_mcontext.arm_r3;
#else
    uintptr_t pc = 0, lr = 0, r0 = 0, r1 = 0, r2 = 0, r3 = 0;
#endif
    char mod[256]; uintptr_t base = 0;
    findModule(pc, mod, sizeof(mod), &base);
    char modLr[256]; uintptr_t baseLr = 0;
    findModule(lr, modLr, sizeof(modLr), &baseLr);

    FILE* f = fopen(LOGFILE, "a");
    if (f) {
        fprintf(f, "==== CRASH ====\n");
        fprintf(f, "signal: %d\nfault_addr: %p\n", sig, info->si_addr);
        fprintf(f, "pc: 0x%lx  module: %s  offset: 0x%lx\n",
                (unsigned long)pc, mod, (unsigned long)(pc - base));
        fprintf(f, "lr(caller): 0x%lx  module: %s  offset: 0x%lx\n",
                (unsigned long)lr, modLr, (unsigned long)(lr - baseLr));
        fprintf(f, "r0: 0x%lx  r1: 0x%lx  r2: 0x%lx  r3: 0x%lx\n",
                (unsigned long)r0, (unsigned long)r1, (unsigned long)r2, (unsigned long)r3);
        fclose(f);
    }
    int idx = (sig==SIGSEGV)?0:(sig==SIGABRT)?1:(sig==SIGBUS)?2:3;
    sigaction(sig, &g_old[idx], nullptr);
    raise(sig);
}

static void install(int sig, int idx) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crashHandler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(sig, &sa, &g_old[idx]);
}

typedef void* (*RwStreamOpenFn)(int, int, void*);
typedef void* (*RpClumpGtaStreamReadFn)(void*);

struct ParamsBufFirst  { void* buffer; uint32_t length; };
struct ParamsLenFirst  { uint32_t length; void* buffer; };

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
    static const char* info = "samplog|2.0|multi-variant clump loader|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() { remove(LOGFILE); remove(TESTLOG); }

EXPORT void OnModLoad() {
    install(SIGSEGV, 0); install(SIGABRT, 1);
    install(SIGBUS, 2);  install(SIGILL, 3);
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "[samplog] handler terpasang v2.0\n"); fclose(f); }
}

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
    if (log) fclose(log);
    return clump;
}

// Variant B: type=3, skip 12-byte header, struct {buffer,length}
EXPORT void* samplog_clump_B(const char* path) {
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
    if (log) fclose(log);
    return clump;
}

// Variant C: type=4, full buffer, struct {buffer,length}  (jaga-jaga kalau enum type beda)
EXPORT void* samplog_clump_C(const char* path) {
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
    if (log) fclose(log);
    return clump;
}

// Variant D: type=3, full buffer, struct DIBALIK {length,buffer}
EXPORT void* samplog_clump_D(const char* path) {
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
    if (log) fclose(log);
    return clump;
}

// Variant E: type=3, skip header, struct DIBALIK {length,buffer}
EXPORT void* samplog_clump_E(const char* path) {
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
    if (log) fclose(log);
    return clump;
}

// Variant F: type=5, full buffer, struct {buffer,length}
EXPORT void* samplog_clump_F(const char* path) {
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
    if (log) fclose(log);
    return clump;
}


typedef void* (*GetHierFromClumpFn)(void*);
typedef void  (*SetFrameHierFn)(void*, void*);
typedef void  (*UpdateMatricesFn)(void*);

EXPORT bool samplog_swap_clump_safe(void* pedPtr, void* newClump) {
    FILE* log = fopen(TESTLOG, "a");
    if (log) fprintf(log, "\n=== SWAP SAFE ===\n");

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
        if (log) fprintf(log, "RpAnimBlendClumpInit dipanggil\n");
    }
    if (CAnimManager_AddAnimation) {
        CAnimManager_AddAnimation(newClump, 0, 3); // group 0, ANIM_STD_IDLE_STANCE (id umum=3)
        void* checkAssoc = GetAnimHierarchyFromClump ? nullptr : nullptr; // placeholder, cek manual di bawah
        if (RpAnimBlendClumpGetFirstAssociation_local) {
            checkAssoc = RpAnimBlendClumpGetFirstAssociation_local(newClump);
        }
        if (log) fprintf(log, "AddAnimation dipanggil, firstAssoc setelah init=%p\n", checkAssoc);
    }

    // RwObject layout: byte type,subType,flags,privateFlags lalu void* parent (frame) di offset 0x4
    void* newFrame = *(void**)((unsigned char*)newClump + 0x4);
    if (log) fprintf(log, "newFrame=%p\n", newFrame);
    if (!newFrame) { if (log) fclose(log); return false; }

    RpHAnimFrameSetHierarchy(newFrame, hier);
    if (RpHAnimHierarchyUpdateMatrices) RpHAnimHierarchyUpdateMatrices(hier);

    *clumpSlot = newClump;
    if (log) { fprintf(log, "SWAP OK\n"); fclose(log); }
    return true;
}



} // extern "C"
