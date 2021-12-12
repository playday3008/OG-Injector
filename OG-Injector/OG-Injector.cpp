#include "OG-Injector.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <thread>

#include <intrin.h>

using namespace std;
namespace fs = filesystem;

// Retrieve the system error message for the last-error code
int ErrorExit(const wstring& lpszFunction)
{
    using namespace termcolor;
#define x xorstr_

    const DWORD dw = pGetLastError();

    if (!dw)
        wcout << x(L"GetLastError() didn't catch anything.") << endl;
    else {
        LPWSTR lpMsgBuf = nullptr;

        pFormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&lpMsgBuf),
            0, nullptr);

        wcout << yellow << x(L"GetLastError()") << reset << x(L" catched error:") << endl;
        wcout << cyan << lpszFunction << reset << x(L" failed with error ") << bright_red << to_wstring(dw) << reset << x(L": ") << bright_yellow << lpMsgBuf << reset << endl;

        pLocalFree(lpMsgBuf);
    }

    _wsystem(x(L"pause"));
#undef x
    exit(dw);
}

inline void PrintLogo()
{
    using namespace termcolor;
    using namespace this_thread;
    using namespace chrono_literals;
#define x xorstr_
    wcout << bright_red     << x(LR"(   ____  ______   ____        _           __)")              << endl; sleep_for(50ms);
    wcout << bright_green   << x(LR"(  / __ \/ ____/  /  _/___    (_)__  _____/ /_____  _____)")  << endl; sleep_for(50ms);
    wcout << bright_yellow  << x(LR"( / / / / / __    / // __ \  / / _ \/ ___/ __/ __ \/ ___/)")  << endl; sleep_for(50ms);
    wcout << bright_blue    << x(LR"(/ /_/ / /_/ /  _/ // / / / / /  __/ /__/ /_/ /_/ / /)")      << endl; sleep_for(50ms);
    wcout << bright_magenta << x(LR"(\____/\____/  /___/_/ /_/_/ /\___/\___/\__/\____/_/)")       << endl; sleep_for(50ms);
    wcout << bright_cyan    << x(LR"(    ____  __           /___/)")                              << endl; sleep_for(50ms);
    wcout << bright_red     << x(LR"(   / __ \/ /___ ___  __/ __ \____ ___  __)")                 << endl; sleep_for(50ms);
    wcout << bright_green   << x(LR"(  / /_/ / / __ `/ / / / / / / __ `/ / / /)")                 << endl; sleep_for(50ms);
    wcout << bright_yellow  << x(LR"( / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /)")                  << endl; sleep_for(50ms);
    wcout << bright_blue    << x(LR"(/_/   /_/\__,_/\__, /_____/\__,_/\__, /)")                   << endl; sleep_for(50ms);
    wcout << bright_magenta << x(LR"(              /____/            /____/)")            << endl << endl; sleep_for(50ms);
    wcout << bright_white   << x(L"Build: " __TIMESTAMP__)                       << reset << endl << endl; sleep_for(50ms);
#undef x
}

inline int InitWinAPI()
{
#define x xorstr_
    wcout << x(L"Loading WinAPI functions") << endl;

    pGetProcAddress = GetProcAddress;
    pGetModuleHandleW = GetModuleHandleW;

    auto kernel32 = pGetModuleHandleW(x(L"kernel32"));
    if (!kernel32) {
        wcout << x(L"Yo, WTF, how I didn't find kernel32 module?") << endl;
        _wsystem(x(L"pause"));
        return EXIT_FAILURE;
    }

    try
    {
#ifdef _DEBUG
        pGetModuleFileNameA = DynamicLoad<LPGETMODULEFILENAMEA>(kernel32, x("GetModuleFileNameA"));
#endif
        pGetLastError = DynamicLoad<LPGETLASTERROR>(kernel32, x("GetLastError"));
        pFormatMessageW = DynamicLoad<LPFORMATMESSAGEW>(kernel32, x("FormatMessageW"));
        pLocalFree = DynamicLoad<LPLOCALFREE>(kernel32, x("LocalFree"));
        pLoadLibraryW = DynamicLoad<LPLOADLIBRARYW>(kernel32, x("LoadLibraryW"));

        pOpenProcess = DynamicLoad<LPOPENPROCESS>(kernel32, x("OpenProcess"));
        pCloseHandle = DynamicLoad<LPCLOSEHANDLE>(kernel32, x("CloseHandle"));
        pVirtualAllocEx = DynamicLoad<LPVIRTUALALLOCEX>(kernel32, x("VirtualAllocEx"));
        pWriteProcessMemory = DynamicLoad<LPWRITEPROCESSMEMORY>(kernel32, x("WriteProcessMemory"));
        pCreateRemoteThread = DynamicLoad<LPCREATEREMOTETHREAD>(kernel32, x("CreateRemoteThread"));

        pCreateToolhelp32Snapshot = DynamicLoad<LPCREATETOOLHELP32SNAPSHOT>(kernel32, x("CreateToolhelp32Snapshot"));
        pProcess32FirstW = DynamicLoad<LPPROCESS32FIRSTW>(kernel32, x("Process32FirstW"));
        pProcess32NextW = DynamicLoad<LPPROCESS32NEXTW>(kernel32, x("Process32NextW"));
    }
    catch (const std::runtime_error& e)
    {
        using namespace termcolor;
        wcout << red << x(L"Can't load '") << bright_red << e.what() << red << x(L"' function for correct dll injection into process") << reset << endl;
        if (pGetLastError && pFormatMessageW && pLocalFree)
            return ErrorExit(x(L"DynamicLoad<>()"));
        else {
            wcout << x("It's probably impossible to read THIS error message, how did you do that?") << endl;
            _wsystem(x(L"pause"));
            return EXIT_FAILURE;
        }
    }

    wcout << x(L"WinAPI functions loaded") << endl;
#undef x
    return EXIT_SUCCESS;
}

inline auto GetLibraryName()
{
    using namespace termcolor;
    wstring lName;
#define x xorstr_
    do {
        wcout << x("Provide a library name (ex. blah.dll): ");
        wcin >> lName;

        wcin.clear();
        if (!fs::exists(lName)) {
            wcout << red << x(L"Can't find: ") << bright_red << lName << reset << endl;
            wcout << yellow << x(L"Try again!") << reset << endl;
            wcin.clear();
            lName.clear();
            continue;
        }
        else {
            auto stream = fstream(lName, ios_base::binary| ios_base::in);
            if (stream.is_open()) {
                uint16_t mzHead = 0;
                uint16_t peOffset = 0;
                uint16_t peHead = 0;

                stream.read(reinterpret_cast<char*>(&mzHead), sizeof mzHead);
                stream.seekg(0x3c, stream.beg);
                stream.read(reinterpret_cast<char*>(&peOffset), sizeof peOffset);
                stream.seekg(peOffset, stream.beg);
                stream.read(reinterpret_cast<char*>(&peHead), sizeof peHead);
                if (mzHead != 0x5a4dUi16 || peHead != 0x00004550Ui16) {
                    wcout << red << x(L"Invalid DLL file") << reset << endl;
                    if (mzHead != 0x5a4dUi16)
                        wcout << red << x(L"P.S. Invalid magic hash") << reset << endl;
                    else if (peHead != 0x4550Ui16)
                        wcout << red << x(L"P.S. Invalid PE header") << reset << endl;
                    wcout << yellow << x(L"Try again!") << reset << endl;
                    lName.clear();
                    continue;
                }

                stream.close();
            }
        }
        break;
    } while (true);

    wcout << green << x(L"DLL '") << bright_green << lName << reset << green << x(L"' found!") << reset << endl;
#undef x
    return lName;
}

inline auto GetProcessId(DWORD& pID, wstring& pName)
{
    using namespace termcolor;
#define x xorstr_
    do {
        wcout << x("Provide a process name (ex. dude.exe): ");
        wcin >> pName;

        wcout << yellow << x(L"Looking for a ") << bright_red << pName << reset << yellow << x(L" process") << reset << endl;

        PROCESSENTRY32W entry{ sizeof(entry) };

        auto* snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (!snapshot) {
            wcout << red << x(L"Failed to create process snapshot: ") << reset << endl;
            return ErrorExit(x(L"CreateToolhelp32Snapshot()"));
        }
        if (pProcess32FirstW(snapshot, &entry)) {
            do {
                if (wstring(entry.szExeFile) == pName)
                    pID = entry.th32ProcessID;
            } while (pProcess32NextW(snapshot, &entry));
        }

        if (!pID) {
            wcout << red << x(L"Couldn't find: ") << bright_red << pName << reset << endl;
            if (!pCloseHandle(snapshot)) {
                wcout << red << x(L"Failed to close process snapshot handle") << reset << endl;
                return ErrorExit(x(L"CloseHandle()"));
            }
            wcout << yellow << x(L"Try again!") << reset << endl;
            wcin.clear();
            pName.clear();
            continue;
        }

        if (!pCloseHandle(snapshot)) {
            wcout << red << x(L"Failed to close process snapshot handle") << reset << endl;
            return ErrorExit(x(L"CloseHandle()"));
        }
        break;
    } while (true);

    wcout << green << x(L"Process: ") << bright_green << pName << reset << green << x(L" found with ID: ") << bright_green << dec << pID << reset << endl;
#undef x
    return EXIT_SUCCESS;
}

inline auto InjectLoadLibrary(const wstring& dllname, const wstring& processName, const DWORD processId)
{
#define x xorstr_
    using namespace termcolor;

    const wstring dllPath = fs::absolute(dllname).wstring();
    vector<wchar_t> dll(MAX_PATH);
    dllPath.copy(dll.data(), dllPath.size() + 1);
    dll.at(dllPath.size()) = '\000';

    wcout << yellow << x(L"Injecting ") << bright_yellow << dllname << reset << yellow << x(L" into ") << bright_yellow << processName << reset << endl;

    auto* hProcess = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
    if (!hProcess) {
        wcout << red << x(L"Can't open ") << bright_red << processName << reset << red << x(L" to write") << reset << endl;
        return ErrorExit(x(L"OpenProcess()"));
    }
    auto* allocatedMem = pVirtualAllocEx(hProcess, nullptr, dll.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMem) {
        wcout << red << x(L"Can't allocate memory in ") << bright_red << processName << reset << endl;
        return ErrorExit(x(L"VirtualAllocEx()"));
    }
    if (!pWriteProcessMemory(hProcess, allocatedMem, dll.data(), dll.size(), nullptr)) {
        wcout << red << x(L"Can't write dll path to ") << bright_red << processName << reset << endl;
        return ErrorExit(x(L"WriteProcessMemory()"));
    }
    auto* thread = pCreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), allocatedMem, 0, nullptr);
    if (!thread) {
        wcout << red << x(L"Can't create remote thread with LoadLibrary module in ") << bright_red << processName << reset << endl;
        return ErrorExit(x(L"CreateRemoteThread()"));
    }
    if (!pCloseHandle(hProcess)) {
        wcout << red << x(L"Can't close ") << bright_red << processName << reset << red << x(L"handle") << reset << endl;
        return ErrorExit(x(L"CloseHandle()"));
    }
#undef x
    return EXIT_SUCCESS;
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
    PrintLogo();

    if (auto ret = InitWinAPI())
        return ret;

    const wstring dllname = GetLibraryName();

    DWORD processId = NULL;
    wstring processName;

    if (auto ret = GetProcessId(processId, processName))
        return ret;

    if (auto ret = InjectLoadLibrary(dllname, processName, processId))
        return ret;

#define x xorstr_
    using namespace termcolor;
    using namespace this_thread;
    using namespace chrono_literals;

    wcout << green << x(L"Successfully injected ") << bright_cyan << dllname << reset << yellow << x(L" into ") << bright_red << processName << reset << endl;
    wcout << bright_white << x(L"You have 5 seconds to read this information, GOODBYE") << reset << endl;
    sleep_for(5s);
#undef x

    return EXIT_SUCCESS;
}
