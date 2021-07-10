#pragma once

#include <iostream>

#include <Windows.h>
#include <TlHelp32.h>

#include "xorstr.hpp"
#include "termcolor.hpp"

typedef FARPROC WINAPI GETPROCADDRESS(
    _In_    HMODULE hModule,
    _In_    LPCSTR  lpProcName
); // GetProcAddress
typedef GETPROCADDRESS FAR* LPGETPROCADDRESS;

typedef _When_(lpModuleName == NULL, _Ret_notnull_) _When_(lpModuleName != NULL, _Ret_maybenull_) HMODULE WINAPI GETMODULEHANDLEW(
    _In_opt_    LPCWSTR lpModuleName
); // GetModuleHandleW
typedef GETMODULEHANDLEW FAR* LPGETMODULEHANDLEW;

typedef _Ret_maybenull_ HMODULE WINAPI LOADLIBRARYW(
    _In_    LPCWSTR lpLibFileName
); // LoadLibraryW
typedef LOADLIBRARYW FAR* LPLOADLIBRARYW;

typedef _Check_return_ _Post_equals_last_error_ DWORD WINAPI GETLASTERROR(); // GetLastError
typedef GETLASTERROR FAR* LPGETLASTERROR;

typedef _Success_(return != 0) DWORD WINAPI FORMATMESSAGEW(
    _In_        DWORD dwFlags,
    _In_opt_    LPCVOID lpSource,
    _In_        DWORD dwMessageId,
    _In_        DWORD dwLanguageId,
    _When_((dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0, _At_((LPWSTR*)lpBuffer, _Outptr_result_z_))
    _When_((dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) == 0, _Out_writes_z_(nSize))
                LPWSTR lpBuffer,
    _In_        DWORD nSize,
    _In_opt_    va_list * Arguments
); // FormatMessageW
typedef FORMATMESSAGEW FAR* LPFORMATMESSAGEW;

typedef _Check_return_ _Post_equals_last_error_ HANDLE WINAPI OPENPROCESS(
    _In_    DWORD   dwDesiredAccess,
    _In_    BOOL    bInheritHandle,
    _In_    DWORD   dwProcessId
); // OpenProcess
typedef OPENPROCESS FAR* LPOPENPROCESS;

typedef BOOL WINAPI CLOSEHANDLE(
    _In_ _Post_ptr_invalid_ HANDLE hObject
); // CloseHandle
typedef CLOSEHANDLE FAR* LPCLOSEHANDLE;

typedef _Ret_maybenull_ _Post_writable_byte_size_(dwSize) LPVOID WINAPI VIRTUALALLOCEX(
    _In_        HANDLE  hProcess,
    _In_opt_    LPVOID  lpAddress,
    _In_        SIZE_T  dwSize,
    _In_        DWORD   flAllocationType,
    _In_        DWORD   flProtect
); // VirtualAllocEx
typedef VIRTUALALLOCEX FAR* LPVIRTUALALLOCEX;

typedef _Success_(return != FALSE) BOOL WINAPI WRITEPROCESSMEMORY(
    _In_                    HANDLE  hProcess,
    _In_                    LPVOID  lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_                    SIZE_T  nSize,
    _Out_opt_               SIZE_T* lpNumberOfBytesWritten
); // WriteProcessMemory
typedef WRITEPROCESSMEMORY FAR* LPWRITEPROCESSMEMORY;

typedef _Ret_maybenull_ HANDLE WINAPI CREATEREMOTETHREAD(
    _In_        HANDLE                  hProcess,
    _In_opt_    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    _In_        SIZE_T                  dwStackSize,
    _In_        LPTHREAD_START_ROUTINE  lpStartAddress,
    _In_opt_    LPVOID                  lpParameter,
    _In_        DWORD                   dwCreationFlags,
    _Out_opt_   LPDWORD                 lpThreadId
); // CreateRemoteThread
typedef CREATEREMOTETHREAD FAR* LPCREATEREMOTETHREAD;

typedef HANDLE WINAPI CREATETOOLHELP32SNAPSHOT(
    DWORD dwFlags,
    DWORD th32ProcessID
); // CreateToolhelp32Snapshot
typedef CREATETOOLHELP32SNAPSHOT FAR* LPCREATETOOLHELP32SNAPSHOT;

typedef BOOL WINAPI PROCESS32FIRSTW(
    HANDLE              hSnapshot,
    LPPROCESSENTRY32W   lppe
); // Process32FirstW
typedef PROCESS32FIRSTW FAR* LPPROCESS32FIRSTW;

typedef BOOL WINAPI PROCESS32NEXTW(
    HANDLE              hSnapshot,
    LPPROCESSENTRY32W   lppe
); // Process32NextW
typedef PROCESS32NEXTW FAR* LPPROCESS32NEXTW;

inline LPGETPROCADDRESS pGetProcAddress;
inline LPGETMODULEHANDLEW pGetModuleHandleW;
inline LPLOADLIBRARYW pLoadLibraryW;
inline LPGETLASTERROR pGetLastError;
inline LPFORMATMESSAGEW pFormatMessageW;
inline LPOPENPROCESS pOpenProcess;
inline LPCLOSEHANDLE pCloseHandle;
inline LPVIRTUALALLOCEX pVirtualAllocEx;
inline LPWRITEPROCESSMEMORY pWriteProcessMemory;
inline LPCREATEREMOTETHREAD pCreateRemoteThread;
inline LPCREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot;
inline LPPROCESS32FIRSTW pProcess32FirstW;
inline LPPROCESS32NEXTW pProcess32NextW;

template <typename LPtypedef>
constexpr auto DynamicLoad(HMODULE Module, const char* Func)
{
#ifdef _DEBUG
    std::cout << xorstr_("Loading function '") << termcolor::green << Func << termcolor::reset << xorstr_("' from module '") << termcolor::yellow << xorstr_("0x") << Module << termcolor::reset << xorstr_("'") << std::endl;
#endif
    auto pModule = reinterpret_cast<LPtypedef>(pGetProcAddress(Module, Func));
    if (!pModule)
#ifdef _DEBUG
        std::cout << xorstr_("Failed to load function") << std::endl;
    else
        std::cout << xorstr_("Function loaded with address '") << termcolor::bright_cyan << xorstr_("0x") << pModule << termcolor::reset << xorstr_("'") << std::endl;
#else
        throw std::runtime_error(Func);
#endif
    return pModule;
}