#include "OG-Injector.hpp"

#if (defined(OSIRIS) || defined(GOESP))
#include <array>
#endif
#include <filesystem>
#include <thread>

using namespace std;

// Process name
#define PROCESS L"csgo.exe"

//#define OSIRIS
//#define GOESP
//#define BETA

#if (defined(OSIRIS) || defined(GOESP))
#include <intrin.h>

inline void checkinst(array<bool, 3>& inst)
{
    array<int, 4> CPUInfo{};
    __cpuid(CPUInfo.data(), 0);
    const auto nIds = CPUInfo.at(0);

    // Detect Features
    if (nIds >= 0x00000001) {
        __cpuid(CPUInfo.data(), 0x00000001);
        inst.at(0) = (CPUInfo.at(3) & 1 << 26) != 0;
        inst.at(1) = (CPUInfo.at(2) & 1 << 28) != 0;
    }
    if (nIds >= 0x00000007) {
        __cpuid(CPUInfo.data(), 0x00000007);
        inst.at(2) = (CPUInfo.at(1) & 1 << 5) != 0;
    }
}
#endif

// Retrieve the system error message for the last-error code
int ErrorExit(const wstring& lpszFunction)
{
    if (!pGetLastError)
        return EXIT_FAILURE;

    const DWORD dw = pGetLastError();

    if (!dw)
        wcout << xorstr_(L"GetLastError() didn't catch anything") << endl;
    else {
        if (!pFormatMessageW)
            return EXIT_FAILURE;

        LPWSTR lpMsgBuf;

        pFormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&lpMsgBuf),
            0, nullptr);

        wcout << termcolor::yellow << xorstr_(L"GetLastError()") << termcolor::reset << xorstr_(L" catched error:") << endl <<
            termcolor::cyan <<
            lpszFunction <<
            termcolor::reset <<
            xorstr_(L" failed with error ") <<
            termcolor::bright_red <<
            to_wstring(dw) <<
            termcolor::reset <<
            xorstr_(L": ") <<
            termcolor::bright_yellow <<
            lpMsgBuf <<
            termcolor::reset <<
            endl;

        pLocalFree(lpMsgBuf);
    }

    _wsystem(xorstr_(L"pause"));

    exit(dw);
}

typedef struct {
    PBYTE baseAddress;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    void(WINAPI* rtlZeroMemory)(void*, size_t);

    DWORD imageBase;
    DWORD relocVirtualAddress;
    DWORD importVirtualAddress;
    DWORD addressOfEntryPoint;
} LoaderData;

DWORD WINAPI RemoteLibraryLoader(LoaderData* loaderData)
{
    auto relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(loaderData->baseAddress + loaderData->relocVirtualAddress);
    const auto delta = reinterpret_cast<DWORD>(loaderData->baseAddress - loaderData->imageBase);
    while (relocation->VirtualAddress) {
        const auto relocationInfo = reinterpret_cast<PWORD>(relocation + 1);
        for (DWORD i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
            if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *reinterpret_cast<PDWORD>(loaderData->baseAddress + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

        relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<LPBYTE>(relocation) + relocation->SizeOfBlock);
    }
    
    auto importDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(loaderData->baseAddress + loaderData->importVirtualAddress);

    while (importDirectory->Characteristics) {
        auto originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(loaderData->baseAddress + importDirectory->OriginalFirstThunk);
        auto firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(loaderData->baseAddress + importDirectory->FirstThunk);

        HMODULE module = loaderData->loadLibraryA(reinterpret_cast<LPCSTR>(loaderData->baseAddress) + importDirectory->Name);

        if (!module)
            return FALSE;

        while (originalFirstThunk->u1.AddressOfData) {
            const auto Function = reinterpret_cast<DWORD>(loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG
                ? reinterpret_cast<LPCSTR>(originalFirstThunk->u1.Ordinal & 0xFFFF)
                : reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(loaderData->baseAddress + originalFirstThunk->u1.AddressOfData)->Name
            ));

            if (!Function)
                return FALSE;

            firstThunk->u1.Function = Function;
            originalFirstThunk++;
            firstThunk++;
        }
        importDirectory++;
    }

    if (loaderData->addressOfEntryPoint) {
        const auto result = reinterpret_cast<DWORD(__stdcall*)(HMODULE, DWORD, LPVOID)>(loaderData->baseAddress + loaderData->addressOfEntryPoint)
            (reinterpret_cast<HMODULE>(loaderData->baseAddress), DLL_PROCESS_ATTACH, nullptr);

        loaderData->rtlZeroMemory(loaderData->baseAddress + loaderData->addressOfEntryPoint, 32);

        return result;
    }
    return TRUE;
}

void stub() {}

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

    wcout << termcolor::bright_red << xorstr_(LR"(   ____  ______   ____        _           __)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_green << xorstr_(LR"(  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_yellow << xorstr_(LR"( / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_blue << xorstr_(LR"(/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_magenta << xorstr_(LR"(\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_cyan << xorstr_(LR"(    ____  __           /___/)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_red << xorstr_(LR"(   / __ \/ /___ ___  __/ __ \____ ___  __)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_green << xorstr_(LR"(  / /_/ / / __ `/ / / / / / / __ `/ / / /)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_yellow << xorstr_(LR"( / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_blue << xorstr_(LR"(/_/   /_/\__,_/\__, /_____/\__,_/\__, /)") << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << termcolor::bright_magenta << xorstr_(LR"(              /____/            /____/)") << endl << endl;
    this_thread::sleep_for(chrono::milliseconds(50));
    wcout << 
        termcolor::bright_white <<
        xorstr_(L"Build: " __TIMESTAMP__) <<
        termcolor::reset << 
        endl << endl;
    this_thread::sleep_for(chrono::milliseconds(50));

    #pragma endregion

    #pragma region WinAPI

    wcout << xorstr_(L"Loading WinAPI functions") << endl;

    pGetProcAddress = GetProcAddress;
    pGetModuleHandleW = GetModuleHandleW;
    auto kernel32 = pGetModuleHandleW(xorstr_(L"kernel32"));
    if (!kernel32)
        return EXIT_FAILURE;

    auto ntdll = pGetModuleHandleW(xorstr_(L"ntdll"));
    if (!ntdll)
        return EXIT_FAILURE;

    try
    {
        pLoadLibraryA = DynamicLoad<LPLOADLIBRARYA>(kernel32, xorstr_("LoadLibraryA"));
        pGetLastError = DynamicLoad<LPGETLASTERROR>(kernel32, xorstr_("GetLastError"));
        pSetLastError = DynamicLoad<LPSETLASTERROR>(kernel32, xorstr_("SetLastError"));
        pFormatMessageW = DynamicLoad<LPFORMATMESSAGEW>(kernel32, xorstr_("FormatMessageW"));
        pRtlZeroMemory = DynamicLoad<LPRTLZEROMEMORY>(kernel32, xorstr_("RtlZeroMemory"));
        pLocalFree = DynamicLoad<LPLOCALFREE>(kernel32, xorstr_("LocalFree"));

        pOpenProcess = DynamicLoad<LPOPENPROCESS>(kernel32, xorstr_("OpenProcess"));
        pCloseHandle = DynamicLoad<LPCLOSEHANDLE>(kernel32, xorstr_("CloseHandle"));
        pVirtualAlloc = DynamicLoad<LPVIRTUALALLOC>(kernel32, xorstr_("VirtualAlloc"));
        pVirtualAllocEx = DynamicLoad<LPVIRTUALALLOCEX>(kernel32, xorstr_("VirtualAllocEx"));
        pVirtualFreeEx = DynamicLoad<LPVIRTUALFREEEX>(kernel32, xorstr_("VirtualFreeEx"));
        pWriteProcessMemory = DynamicLoad<LPWRITEPROCESSMEMORY>(kernel32, xorstr_("WriteProcessMemory"));
        pWaitForSingleObject = DynamicLoad<LPWAITFORSINGLEOBJECT>(kernel32, xorstr_("WaitForSingleObject"));

        pCreateToolhelp32Snapshot = DynamicLoad<LPCREATETOOLHELP32SNAPSHOT>(kernel32, xorstr_("CreateToolhelp32Snapshot"));
        pProcess32FirstW = DynamicLoad<LPPROCESS32FIRSTW>(kernel32, xorstr_("Process32FirstW"));
        pProcess32NextW = DynamicLoad<LPPROCESS32NEXTW>(kernel32, xorstr_("Process32NextW"));
        
        pCreateFileW = DynamicLoad<LPCREATEFILEW>(kernel32, xorstr_("CreateFileW"));
        pGetFileSize = DynamicLoad<LPGETFILESIZE>(kernel32, xorstr_("GetFileSize"));
        pReadFile = DynamicLoad<LPREADFILE>(kernel32, xorstr_("ReadFile"));
        
        pRtlCreateUserThread = DynamicLoad<LPRTLCREATEUSERTHREAD>(ntdll, xorstr_("RtlCreateUserThread"));
        pRtlNtStatusToDosError = DynamicLoad<LPRTLNTSTATUSTODOSERROR>(ntdll, xorstr_("RtlNtStatusToDosError"));
    }
    catch (const std::runtime_error& e)
    {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't load '") <<
            termcolor::yellow <<
            e.what() <<
            termcolor::red <<
            xorstr_(L"' function to correct dll injection into process") <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"DynamicLoad<>()"));
    }

    wcout << xorstr_(L"WinAPI functions loaded") << endl;

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
    dllname += xorstr_(L"_BETA");
    #endif

    #if (defined(OSIRIS) || defined(GOESP))
    // Get processor instructions
    array<bool, 3> inst{};
    checkinst(inst);

    if (inst.at(2))
        dllname += xorstr_(L"_AVX2.dll");
    else if (inst.at(1))
        dllname += xorstr_(L"_AVX.dll");
    else if (inst.at(0))
        dllname += xorstr_(L"_SSE2.dll");
    #endif

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
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't find: ") << 
            termcolor::bright_red <<
            dllname << 
            termcolor::reset << 
            endl;
        _wsystem(xorstr_(L"pause"));
        return EXIT_FAILURE;
    }

    #pragma endregion

    #pragma region Find process

    const wstring processName = xorstr_(PROCESS);
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

    DWORD processId = NULL;
    PROCESSENTRY32W entry{ sizeof entry };

    auto* snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (!snapshot) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't create process snapshot: ") <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"CreateToolhelp32Snapshot()"));
    }
    if (pProcess32FirstW(snapshot, &entry))
        do {
            if (wstring(entry.szExeFile) == processName)
                processId = entry.th32ProcessID;
        } while (pProcess32NextW(snapshot, &entry));

    if (!processId) {
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't find: ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            endl;
        _wsystem(xorstr_(L"pause"));
        return EXIT_FAILURE;
    }

    if (!pCloseHandle(snapshot)) {
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
        return ErrorExit(xorstr_(L"CloseHandle()"));
    }

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

    #pragma region Injection code

    const wstring dllPath = filesystem::absolute(dllname);
    vector<wchar_t> dll(MAX_PATH);
    dllPath.copy(dll.data(), dllPath.size() + 1);
    dll.at(dllPath.size()) = '\0';

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
    
    auto* hFile = pCreateFileW(dll.data(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't open ") <<
            termcolor::bright_red <<
            dll.data() <<
            termcolor::reset <<
            termcolor::red <<
            xorstr_(L" to read") <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"CreateFileW()"));
    }
    const auto FileSize = pGetFileSize(hFile, nullptr);
    if (FileSize == INVALID_FILE_SIZE) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Invalid size of ") <<
            termcolor::bright_red <<
            dll.data() <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"GetFileSize()"));
    }
    auto FileBuffer = pVirtualAlloc(nullptr, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!FileBuffer) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't allocate memory for ") <<
            termcolor::bright_red <<
            dll.data() <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"VirtualAlloc()"));
    }
    if (!pReadFile(hFile, FileBuffer, FileSize, nullptr, nullptr)) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't read ") <<
            termcolor::bright_red <<
            dll.data() <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"ReadFile()"));
    }

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<LPBYTE>(FileBuffer) + static_cast<PIMAGE_DOS_HEADER>(FileBuffer)->e_lfanew);
    auto* hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
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
        return ErrorExit(xorstr_(L"OpenProcess()"));
    }
    auto* executableImage = static_cast<PBYTE>(pVirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!executableImage) {
        wcout << 
            termcolor::red << 
            xorstr_(L"Can't allocate memory in ") << 
            termcolor::bright_red <<
            processName << 
            termcolor::reset << 
            endl;
        return ErrorExit(xorstr_(L"VirtualAllocEx()"));
    }
    //if (!pWriteProcessMemory(hProcess, executableImage, FileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
    //    wcout <<
    //        termcolor::red <<
    //        xorstr_(L"Can't write injection data into ") <<
    //        termcolor::bright_red <<
    //        processName <<
    //        termcolor::reset <<
    //        endl;
    //    return ErrorExit(xorstr_(L"WriteProcessMemory()"));
    //}
    const auto sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(ntHeaders + 1);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        if (!pWriteProcessMemory(hProcess, executableImage + sectionHeaders[i].VirtualAddress, static_cast<LPBYTE>(FileBuffer) + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, nullptr)) {
            wcout <<
                termcolor::red <<
                xorstr_(L"Can't write dll into ") <<
                termcolor::bright_red <<
                processName <<
                termcolor::reset <<
                termcolor::bright_red <<
                xorstr_(L" (part ") << i << xorstr_(L" of ") << ntHeaders->FileHeader.NumberOfSections << xorstr_(L")") <<
                termcolor::reset <<
                endl;
            return ErrorExit(xorstr_(L"WriteProcessMemory()"));
        }
    auto loaderMemory = static_cast<LoaderData*>(pVirtualAllocEx(hProcess, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
    if (!loaderMemory) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't allocate memory for injection code in ") <<
            termcolor::reset <<
            termcolor::bright_red <<
            processName <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"VirtualAllocEx()"));
    }

    LoaderData loaderParams{
        executableImage,
        pLoadLibraryA,
        pGetProcAddress,
        pRtlZeroMemory,
        ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
        ntHeaders->OptionalHeader.AddressOfEntryPoint
    };
    
    if (!pWriteProcessMemory(hProcess, loaderMemory, &loaderParams, sizeof(LoaderData), nullptr)) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't write injection data into ") <<
            termcolor::bright_red <<
            processName <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"WriteProcessMemory()"));
    }
    if (!pWriteProcessMemory(hProcess, loaderMemory + 1, RemoteLibraryLoader, reinterpret_cast<DWORD>(stub) - reinterpret_cast<DWORD>(RemoteLibraryLoader), nullptr)) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't write injection data into ") <<
            termcolor::bright_red <<
            processName <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"WriteProcessMemory()"));
    }
    auto* thread = INVALID_HANDLE_VALUE;
    auto status = pRtlCreateUserThread(hProcess, nullptr, 0, 0, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loaderMemory + 1), loaderMemory, &thread, nullptr);
    if (!(status >= 0)) {
        pSetLastError(pRtlNtStatusToDosError(status));
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't create remote thread with injection function in ") <<
            termcolor::bright_red <<
            processName <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"RtlCreateUserThread()"));
    }
    pWaitForSingleObject(thread, INFINITE);
    if (!pVirtualFreeEx(hProcess, loaderMemory, 0, MEM_RELEASE)) {
        wcout <<
            termcolor::red <<
            xorstr_(L"Can't free virtual memory after injection in ") <<
            termcolor::bright_red <<
            processName <<
            termcolor::reset <<
            endl;
        return ErrorExit(xorstr_(L"VirtualFreeEx()"));
    }
    if (!pCloseHandle(hProcess)) {
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
        return ErrorExit(xorstr_(L"CloseHandle()"));
    }

    #pragma endregion

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
    wcout <<
        termcolor::bright_white <<
        xorstr_(L"You have 5 seconds to read this information, GOODBYE") <<
        termcolor::reset <<
        endl;
    this_thread::sleep_for(chrono::seconds(5));

    return EXIT_SUCCESS;
}
