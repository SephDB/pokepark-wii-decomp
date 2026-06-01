extern "C" {
void DVDInit();
void VIInit();
void PADInit();
unsigned long OSGetTick();
void srand(unsigned long seed);
void initMemoryAlloc();
void fn_802ED900(int);
void fn_802ED910();
void fn_802EDC70();
void InitSyscall0Page();
void InitMainRecordTable();
void SetSyscallPage1();
}

struct flMemoryManager {
    char _[0x4C];
    void init(int size, int param);
    void clear();
};

extern flMemoryManager flMemoryMutex;

namespace flRevolutionAlloc {
void clear();
}

extern "C" void flOSInit() {
    DVDInit();
    VIInit();
    PADInit();
    initMemoryAlloc();
    fn_802ED900(1);
    flMemoryMutex.init(0x500000, 0);
    srand(OSGetTick());
    InitSyscall0Page();
    InitMainRecordTable();
    SetSyscallPage1();
}

extern "C" void fn_802F3430() {
    fn_802EDC70();
    flMemoryMutex.clear();
    fn_802ED910();
    flRevolutionAlloc::clear();
}
