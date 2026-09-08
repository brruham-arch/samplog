#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#define LOGFILE "/storage/emulated/0/samplog_crash.txt"
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
#elif defined(__aarch64__)
    uintptr_t pc = uc->uc_mcontext.pc;
#else
    uintptr_t pc = 0;
#endif
    char mod[256]; uintptr_t base = 0;
    findModule(pc, mod, sizeof(mod), &base);

    FILE* f = fopen(LOGFILE, "a");
    if (f) {
        fprintf(f, "==== CRASH ====\n");
        fprintf(f, "signal: %d\nfault_addr: %p\npc: 0x%lx\n", sig, info->si_addr, (unsigned long)pc);
        fprintf(f, "module: %s\nmodule_base: 0x%lx\noffset_in_module: 0x%lx\n",
                mod, (unsigned long)base, (unsigned long)(pc - base));
        fclose(f);
    }

    int idx = (sig==SIGSEGV)?0:(sig==SIGABRT)?1:(sig==SIGBUS)?2:3;
    sigaction(sig, &g_old[idx], nullptr);
    raise(sig); // lanjut ke default handler, game tetap FC seperti biasa
}

static void install(int sig, int idx) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crashHandler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(sig, &sa, &g_old[idx]);
}

extern "C" {
EXPORT void* __GetModInfo() {
    static const char* info = "samplog|1.0|Native crash logger (module+offset)|brruham";
    return (void*)info;
}
EXPORT void OnModPreLoad() { remove(LOGFILE); }
EXPORT void OnModLoad() {
    install(SIGSEGV, 0); install(SIGABRT, 1);
    install(SIGBUS, 2);  install(SIGILL, 3);
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "[samplog] handler terpasang\n"); fclose(f); }
}
}