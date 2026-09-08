#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "samplog|1.3|crash logger + memory-stream clump loader|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() { remove(LOGFILE); remove(TESTLOG); }

EXPORT void OnModLoad() {
    install(SIGSEGV, 0); install(SIGABRT, 1);
    install(SIGBUS, 2);  install(SIGILL, 3);
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "[samplog] handler terpasang v1.3\n"); fclose(f); }
}

EXPORT int samplog_test_fopen(const char* path) {
    FILE* f = fopen(path, "rb");
    FILE* log = fopen(TESTLOG, "a");
    if (!f) {
        if (log) { fprintf(log, "[testfopen] path=%s GAGAL fopen\n", path); fclose(log); }
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    if (log) { fprintf(log, "[testfopen] path=%s SUKSES, size=%ld bytes\n", path, size); fclose(log); }
    return (int)size;
}

typedef void* (*RwStreamOpenFn)(int, int, void*);
typedef void* (*RpClumpGtaStreamReadFn)(void*);

struct RwMemStreamParams {
    void* buffer;
    uint32_t length;
};

EXPORT void* samplog_load_clump_from_file(const char* path) {
    FILE* log = fopen(TESTLOG, "a");
    #define LOGT(...) do { if (log) { fprintf(log, __VA_ARGS__); fflush(log); } } while(0)

    LOGT("[loadclump] mulai path=%s\n", path);

    FILE* f = fopen(path, "rb");
    if (!f) { LOGT("[loadclump] fopen gagal\n"); if (log) fclose(log); return nullptr; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    LOGT("[loadclump] size=%ld\n", size);

    void* buf = malloc(size);
    if (!buf) { LOGT("[loadclump] malloc gagal\n"); fclose(f); if (log) fclose(log); return nullptr; }

    size_t rd = fread(buf, 1, size, f);
    fclose(f);
    LOGT("[loadclump] fread=%zu\n", rd);

    {
        unsigned char* b = (unsigned char*)buf;
        LOGT("[loadclump] header bytes: %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X\n",
             b[0],b[1],b[2],b[3], b[4],b[5],b[6],b[7], b[8],b[9],b[10],b[11]);
        uint32_t chunkId = b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24);
        uint32_t chunkSize = b[4] | (b[5]<<8) | (b[6]<<16) | (b[7]<<24);
        LOGT("[loadclump] chunkId=0x%X chunkSize=%u (fileSize-12=%ld)\n", chunkId, chunkSize, size-12);
    }

    static RwStreamOpenFn RwStreamOpen = nullptr;
    static RpClumpGtaStreamReadFn RpClumpGtaStreamRead = nullptr;
    if (!RwStreamOpen) {
        void* hGtasa = dlopen("libGTASA.so", RTLD_NOW);
        LOGT("[loadclump] dlopen libGTASA.so handle=%p\n", hGtasa);
        if (hGtasa) {
            RwStreamOpen = (RwStreamOpenFn)dlsym(hGtasa, "_Z12RwStreamOpen12RwStreamType18RwStreamAccessTypePKv");
            RpClumpGtaStreamRead = (RpClumpGtaStreamReadFn)dlsym(hGtasa, "_Z20RpClumpGtaStreamReadP8RwStream");
        }
    }
    LOGT("[loadclump] RwStreamOpen=%p RpClumpGtaStreamRead=%p\n", (void*)RwStreamOpen, (void*)RpClumpGtaStreamRead);

    if (!RwStreamOpen || !RpClumpGtaStreamRead) {
        LOGT("[loadclump] dlsym gagal\n");
        free(buf); if (log) fclose(log); return nullptr;
    }

    RwMemStreamParams params;
    params.buffer = buf;
    params.length = (uint32_t)size;

    LOGT("[loadclump] sebelum RwStreamOpen (type=3 memory)\n");
    void* stream = RwStreamOpen(3, 1, &params);
    LOGT("[loadclump] sesudah RwStreamOpen stream=%p\n", stream);

    if (!stream) {
        LOGT("[loadclump] stream NULL\n");
        free(buf); if (log) fclose(log); return nullptr;
    }

    LOGT("[loadclump] sebelum RpClumpGtaStreamRead\n");
    void* clump = RpClumpGtaStreamRead(stream);
    LOGT("[loadclump] sesudah RpClumpGtaStreamRead clump=%p\n", clump);

    if (log) fclose(log);
    return clump;
}

} // extern "C"
