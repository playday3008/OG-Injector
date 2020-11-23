#pragma once

#include <array>
#include <filesystem>
#include <iostream>
#include <thread>

#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>

#include "xorstr.hpp"

typedef FARPROC WINAPI GETPROCADDRESS(
    _In_    HMODULE hModule,
    _In_    LPCSTR  lpProcName
); // GetProcAddress
typedef GETPROCADDRESS FAR* LPGETPROCADDRESS;

typedef HMODULE WINAPI GETMODULEHANDLEW(
    _In_opt_    LPCWSTR lpModuleName
); // GetModuleHandleW
typedef GETMODULEHANDLEW FAR* LPGETMODULEHANDLEW;

typedef HMODULE WINAPI LOADLIBRARYW(
    _In_    LPCWSTR lpLibFileName
); // LoadLibraryW
typedef LOADLIBRARYW FAR* LPLOADLIBRARYW;

typedef HANDLE WINAPI OPENPROCESS(
    _In_    DWORD   dwDesiredAccess,
    _In_    BOOL    bInheritHandle,
    _In_    DWORD   dwProcessId
); // OpenProcess
typedef OPENPROCESS FAR* LPOPENPROCESS;

typedef BOOL WINAPI CLOSEHANDLE(
    _In_ _Post_ptr_invalid_ HANDLE hObject
); // pCloseHandle
typedef CLOSEHANDLE FAR* LPCLOSEHANDLE;

typedef BOOL WINAPI SETPROCESSMITIGATIONPOLICY(
    _In_                        PROCESS_MITIGATION_POLICY   MitigationPolicy,
    _In_reads_bytes_(dwLength)  PVOID                       lpBuffer,
    _In_                        SIZE_T                      dwLength
); // SetProcessMitigationPolicy
typedef SETPROCESSMITIGATIONPOLICY FAR* LPSETPROCESSMITIGATIONPOLICY;

typedef LPVOID WINAPI VIRTUALALLOCEX(
    _In_        HANDLE  hProcess,
    _In_opt_    LPVOID  lpAddress,
    _In_        SIZE_T  dwSize,
    _In_        DWORD   flAllocationType,
    _In_        DWORD   flProtect
); // VirtualAllocEx
typedef VIRTUALALLOCEX FAR* LPVIRTUALALLOCEX;

typedef BOOL WINAPI WRITEPROCESSMEMORY(
    _In_                    HANDLE  hProcess,
    _In_                    LPVOID  lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_                    SIZE_T  nSize,
    _Out_opt_               SIZE_T* lpNumberOfBytesWritten
); // WriteProcessMemory
typedef WRITEPROCESSMEMORY FAR* LPWRITEPROCESSMEMORY;

typedef HANDLE WINAPI CREATEREMOTETHREAD(
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

LPGETPROCADDRESS pGetProcAddress;
LPGETMODULEHANDLEW pGetModuleHandleW;
LPLOADLIBRARYW pLoadLibraryW;
LPOPENPROCESS pOpenProcess;
LPCLOSEHANDLE pCloseHandle;
LPSETPROCESSMITIGATIONPOLICY pSetProcessMitigationPolicy;
LPVIRTUALALLOCEX pVirtualAllocEx;
LPWRITEPROCESSMEMORY pWriteProcessMemory;
LPCREATEREMOTETHREAD pCreateRemoteThread;
LPCREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot;
LPPROCESS32FIRSTW pProcess32FirstW;
LPPROCESS32NEXTW pProcess32NextW;

template <typename LPtypedef>
__forceinline constexpr auto DynamicLoad(HMODULE Module, const char* Func)
{
    return reinterpret_cast<LPtypedef>(pGetProcAddress(Module, Func));
};