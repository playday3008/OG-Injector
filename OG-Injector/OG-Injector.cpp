#include "OG-Injector.hpp"

#include <array>
#include <filesystem>
#include <thread>

// Process name
#define PROCESS L"csgo.exe"

//#define OSIRIS
//#define GOESP
//#define BETA

#if (defined(OSIRIS) || defined(GOESP))
#include <intrin.h>

inline void checkinst(array<bool, 3>& inst)
{
    JUNK;
    array<int, 4> CPUInfo{};
    JUNK;
    __cpuid(CPUInfo.data(), 0);
    JUNK;
    const auto nIds = CPUInfo.at(0);
    JUNK;

    // Detect Features
    if (nIds >= 0x00000001) {
        JUNK;
        __cpuid(CPUInfo.data(), 0x00000001);
        JUNK;
        inst.at(0) = (CPUInfo.at(3) & 1 << 26) != 0;
        JUNK;
        inst.at(1) = (CPUInfo.at(2) & 1 << 28) != 0;
        JUNK;
    }
    JUNK;
    if (nIds >= 0x00000007) {
        JUNK;
        __cpuid(CPUInfo.data(), 0x00000007);
        JUNK;
        inst.at(2) = (CPUInfo.at(1) & 1 << 5) != 0;
        JUNK;
    }
    JUNK;
}
#endif

int ErrorExit(const wstring& lpszFunction)
{
    JUNK;
    // Retrieve the system error message for the last-error code
    if (!(pGetLastError && pFormatMessageW))
        return EXIT_FAILURE;

    JUNK;
    const DWORD dw = pGetLastError();
    JUNK;

    if (!dw)
        wcout << xorstr_(L"GetLastError() didn't catch anything") << endl;
    else {
        JUNK;
        LPWSTR lpMsgBuf;
        JUNK;

        pFormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&lpMsgBuf),
            0, nullptr);
        JUNK;

        wcout << xorstr_("GetLastError() catched error:") << endl <<
            lpszFunction <<
            xorstr_(L" failed with error ") <<
            to_wstring(dw) <<
            xorstr_(L": ") <<
            lpMsgBuf <<
            endl;
        JUNK;

        LocalFree(lpMsgBuf);
        JUNK;
    }
    JUNK;

    _wsystem(xorstr_(L"pause"));
    JUNK;

    exit(dw);
    JUNK;
}

inline int bypass(const DWORD dwProcess)
{
    // Restore original NtOpenFile from external process
    //credits: Daniel Krupiñski(pozdro dla ciebie byczku <3)
    JUNK;
    auto csgoProcessHandle = pOpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);
    JUNK;
    if (!csgoProcessHandle) {
        JUNK;
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't open csgo.exe to bypass LoadLibrary injection") <<
            termcolor::reset <<
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"OpenProcess"));
    }
    JUNK;
    auto ntdll = pLoadLibraryW(xorstr_(L"ntdll"));
    JUNK;
    if (!ntdll) {
        JUNK;
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't load ntdll.dll module") <<
            termcolor::reset <<
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"LoadLibraryW"));
    }
    JUNK;

    if (auto ntOpenFile = pGetProcAddress(ntdll, xorstr_("NtOpenFile"));
        ntOpenFile) {
        JUNK;
        array<char, 5> originalBytes{};
        JUNK;
        if (memcpy_s(originalBytes.data(), originalBytes.size(), ntOpenFile, 5)) {
            JUNK;
            wcout <<
                termcolor::red <<
                xorstr_(L"Can't copy original NtOpenFile bytes to buffer") <<
                termcolor::reset <<
                endl;
            JUNK;
            return ErrorExit(xorstr_(L"memcpy_s"));
        }
        JUNK;
        if (!pWriteProcessMemory(csgoProcessHandle, ntOpenFile, originalBytes.data(), 5, nullptr)) {
            JUNK;
            wcout <<
                termcolor::red <<
                xorstr_(L"Can't write original NtOpenFile bytes to csgo.exe") <<
                termcolor::reset <<
                endl;
            JUNK;
            return ErrorExit(xorstr_(L"WriteProcessMemory"));
        }
        JUNK;
        if (!pCloseHandle(csgoProcessHandle)) {
            JUNK;
            wcout <<
                termcolor::red <<
                xorstr_(L"Can't close csgo.exe bypass handle") <<
                termcolor::reset <<
                endl;
            JUNK;
            return ErrorExit(xorstr_(L"CloseHandle"));
        }
        JUNK;
        return EXIT_SUCCESS;
    }
    JUNK;
    wcout <<
        termcolor::red <<
        xorstr_(L"Can't get NtOpenFile from ntdll.dll") <<
        termcolor::reset <<
        endl;
    JUNK;
    return ErrorExit(xorstr_(L"GetProcAddress"));
}

//   ____    ___                      ____
//  /\  _`\ /\_ \                    /\  _`\
//  \ \ \L\ \//\ \      __     __  __\ \ \/\ \     __     __  __
//   \ \ ,__/ \ \ \   /'__`\  /\ \/\ \\ \ \ \ \  /'__`\  /\ \/\ \
//    \ \ \/   \_\ \_/\ \L\.\_\ \ \_\ \\ \ \_\ \/\ \L\.\_\ \ \_\ \
//     \ \_\   /\____\ \__/.\_\\/`____ \\ \____/\ \__/.\_\\/`____ \
//      \/_/   \/____/\/__/\/_/ `/___/> \\/___/  \/__/\/_/ `/___/> \
//                                 /\___/                     /\___/
//

int wmain()
{
    #pragma region Logo

    wcout << termcolor::bright_red << xorstr_(LR"(   ____  ______   ____        _           __)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_green << xorstr_(LR"(  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_yellow << xorstr_(LR"( / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_blue << xorstr_(LR"(/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_magenta << xorstr_(LR"(\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_cyan << xorstr_(LR"(    ____  __           /___/)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_red << xorstr_(LR"(   / __ \/ /___ ___  __/ __ \____ ___  __)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_green << xorstr_(LR"(  / /_/ / / __ `/ / / / / / / __ `/ / / /)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_yellow << xorstr_(LR"( / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_blue << xorstr_(LR"(/_/   /_/\__,_/\__, /_____/\__,_/\__, /)") << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << termcolor::bright_magenta << xorstr_(LR"(              /____/            /____/)") << endl << endl; JUNK;
    this_thread::sleep_for(chrono::milliseconds(50)); JUNK;
    wcout << 
        termcolor::bright_white <<
        xorstr_(L"Build: " __TIMESTAMP__) <<
        termcolor::reset << 
        endl << endl;
    JUNK;
    this_thread::sleep_for(chrono::milliseconds(50));
    JUNK;

    #pragma endregion

    #pragma region WinAPI

    wcout << xorstr_(L"Loading WinAPI functions") << endl;
    JUNK;

    pGetProcAddress = GetProcAddress;
    JUNK;
    pGetModuleHandleW = GetModuleHandleW;
    JUNK;
    auto kernel32 = pGetModuleHandleW(xorstr_(L"kernel32"));
    JUNK;
    if (!kernel32)
        return EXIT_FAILURE;

    JUNK;
    pLoadLibraryW = DynamicLoad<LPLOADLIBRARYW>(kernel32, xorstr_("LoadLibraryW"));
    JUNK;
    pGetLastError = DynamicLoad<LPGETLASTERROR>(kernel32, xorstr_("GetLastError"));
    JUNK;
    pFormatMessageW = DynamicLoad<LPFORMATMESSAGEW>(kernel32, xorstr_("FormatMessageW"));
    JUNK;

    pOpenProcess = DynamicLoad<LPOPENPROCESS>(kernel32, xorstr_("OpenProcess"));
    JUNK;
    pCloseHandle = DynamicLoad<LPCLOSEHANDLE>(kernel32, xorstr_("CloseHandle"));
    JUNK;
    pVirtualAllocEx = DynamicLoad<LPVIRTUALALLOCEX>(kernel32, xorstr_("VirtualAllocEx"));
    JUNK;
    pWriteProcessMemory = DynamicLoad<LPWRITEPROCESSMEMORY>(kernel32, xorstr_("WriteProcessMemory"));
    JUNK;
    pCreateRemoteThread = DynamicLoad<LPCREATEREMOTETHREAD>(kernel32, xorstr_("CreateRemoteThread"));
    JUNK;

    pCreateToolhelp32Snapshot = DynamicLoad<LPCREATETOOLHELP32SNAPSHOT>(kernel32, xorstr_("CreateToolhelp32Snapshot"));
    JUNK;
    pProcess32FirstW = DynamicLoad<LPPROCESS32FIRSTW>(kernel32, xorstr_("Process32FirstW"));
    JUNK;
    pProcess32NextW = DynamicLoad<LPPROCESS32NEXTW>(kernel32, xorstr_("Process32NextW"));
    JUNK;

    if (!pGetProcAddress                || !pGetModuleHandleW            ||
        !pLoadLibraryW                    || !pGetLastError                ||
        !pFormatMessageW                || !pOpenProcess                ||
        !pCloseHandle                    || !pVirtualAllocEx                ||
        !pWriteProcessMemory            || !pCreateRemoteThread            ||
        !pCreateToolhelp32Snapshot        || !pProcess32FirstW            ||
        !pProcess32NextW) 
    {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't load needed functions to correct dll injection into process") << 
            termcolor::reset << 
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"DynamicLoad"));
    }
    JUNK;

    wcout << xorstr_(L"WinAPI functions loaded") << endl;
    JUNK;

    #pragma endregion

    #pragma region Osiris and GOESP part

    #ifdef OSIRIS
    wstring dllname = xorstr_(L"Osiris");
    #elif defined(GOESP)
    wstring dllname = xorstr_(L"GOESP");
    #else
    const wstring dllname = xorstr_(L"library.dll");
    #endif

    #if (defined(OSIRIS) || defined(GOESP)) && defined(BETA)
    JUNK;
    dllname += xorstr_(L"_BETA");
    #endif

    #if (defined(OSIRIS) || defined(GOESP))
    // Get processor instructions
    JUNK;
    array<bool, 3> inst{};
    JUNK;
    checkinst(inst);

    JUNK;
    if (inst.at(2))
        dllname += xorstr_(L"_AVX2.dll");
    else if (inst.at(1))
        dllname += xorstr_(L"_AVX.dll");
    else if (inst.at(0))
        dllname += xorstr_(L"_SSE2.dll");
    JUNK;
    #endif

    JUNK;
    if (filesystem::exists(dllname))
        wcout <<
            termcolor::green <<
            xorstr_(L"DLL: ") <<
            termcolor::bright_green <<
            dllname <<
            termcolor::reset <<
            termcolor::green <<
            xorstr_(L" found") <<
            termcolor::reset <<
            endl;
    else {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't find: ") << 
            termcolor::bright_red <<
            dllname << 
            termcolor::reset << 
            endl;
        JUNK;
        _wsystem(xorstr_(L"pause"));
        JUNK;
        return EXIT_FAILURE;
    }
    JUNK;

    #pragma endregion

    #pragma region Find process

    const wstring processName = xorstr_(PROCESS);
    JUNK;
    wcout <<
        termcolor::yellow <<
        xorstr_(L"Finding ") <<
        termcolor::bright_red <<
        processName <<
        termcolor::reset <<
        termcolor::yellow <<
        xorstr_(L" process") <<
        termcolor::reset <<
        endl;

    JUNK;
    DWORD processId = NULL;
    JUNK;
    PROCESSENTRY32W entry{ sizeof entry };
    JUNK;

    auto* snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    JUNK;
    if (!snapshot) {
        JUNK;
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't create process snapshot: ") <<
            termcolor::reset <<
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"CreateToolhelp32Snapshot"));
    }
    JUNK;
    if (pProcess32FirstW(snapshot, &entry))
        do {
            JUNK;
            if (wstring(entry.szExeFile) == processName)
                processId = entry.th32ProcessID;
        } while (pProcess32NextW(snapshot, &entry));

    JUNK;
    if (!processId) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't find: ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            endl;
        JUNK;
        _wsystem(xorstr_(L"pause"));
        JUNK;
        return EXIT_FAILURE;
    }

    JUNK;
    if (!pCloseHandle(snapshot)) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't close ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            termcolor::red << 
            xorstr_(L" finder handle") << 
            termcolor::reset << 
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"CloseHandle"));
    }

    JUNK;
    wcout <<
        termcolor::green <<
        xorstr_(L"Process: ") <<
        termcolor::bright_green <<
        processName <<
        termcolor::reset <<
        termcolor::green <<
        xorstr_(L" found with PID: ") <<
        termcolor::bright_green <<
        dec << processId <<
        termcolor::reset <<
        endl;

    #pragma endregion

    JUNK;
    // Bypass LoadLibrary injection for csgo
    if (bypass(processId) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    #pragma region Injection code

    JUNK;
    const wstring dllPath = filesystem::absolute(dllname);
    JUNK;
    vector<wchar_t> dll(MAX_PATH);
    JUNK;
    dllPath.copy(dll.data(), dllPath.size() + 1);
    JUNK;
    dll.at(dllPath.size()) = '\0';
    JUNK;

    wcout <<
        termcolor::yellow <<
        xorstr_(L"Injecting ") <<
        termcolor::bright_yellow <<
        dllname <<
        termcolor::reset <<
        termcolor::yellow <<
        xorstr_(L" into ") <<
        termcolor::bright_yellow <<
        processName <<
        termcolor::reset <<
        endl;

    JUNK;
    auto* hProcess = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
    JUNK;
    if (!hProcess) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't open ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            termcolor::red << 
            xorstr_(L" to write") <<
            termcolor::reset <<
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"OpenProcess"));
    }
    JUNK;
    auto* allocatedMem = pVirtualAllocEx(hProcess, nullptr, dll.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    JUNK;
    if (!allocatedMem) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't allocate memory in ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"VirtualAllocEx"));
    }
    JUNK;
    if (!pWriteProcessMemory(hProcess, allocatedMem, dll.data(), dll.size(), nullptr)) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't write dll path to ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"WriteProcessMemory"));
    }
    JUNK;
    auto* thread = pCreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), allocatedMem, 0, nullptr);
    JUNK;
    if (!thread) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't create remote thread with LoadLibrary module in ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"CreateRemoteThread"));
    }
    JUNK;
    if (!pCloseHandle(hProcess)) {
        JUNK;
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't close ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            termcolor::red << 
            xorstr_(L"handle") << 
            termcolor::reset << 
            endl;
        JUNK;
        return ErrorExit(xorstr_(L"CloseHandle"));
    }

    #pragma endregion

    JUNK;
    wcout <<
        termcolor::green <<
        xorstr_(L"Successfully injected ") <<
        termcolor::bright_cyan <<
        dllname <<
        termcolor::reset <<
        termcolor::yellow <<
        xorstr_(L" into ") <<
        termcolor::bright_red <<
        processName <<
        termcolor::reset <<
        endl;
    JUNK;
    wcout <<
        termcolor::bright_white <<
        xorstr_(L"You have 10 seconds to read this information, GOODBYE") <<
        termcolor::reset <<
        endl;
    JUNK;
    this_thread::sleep_for(chrono::seconds(10));
    JUNK;

    return EXIT_SUCCESS;
}
