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

typedef _Ret_maybenull_ HMODULE WINAPI LOADLIBRARYA(
    _In_    LPCSTR lpLibFileName
); // LoadLibraryA
typedef LOADLIBRARYA FAR* LPLOADLIBRARYA;

typedef _Check_return_ _Post_equals_last_error_ DWORD WINAPI GETLASTERROR(); // GetLastError
typedef GETLASTERROR FAR* LPGETLASTERROR;

typedef void WINAPI SETLASTERROR(
    _In_ DWORD dwErrCode
); // SetLastError
typedef SETLASTERROR FAR* LPSETLASTERROR;

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

typedef void WINAPI RTLZEROMEMORY(
    void*   Destination,
    size_t  Length
); // RtlZeroMemory
typedef RTLZEROMEMORY FAR* LPRTLZEROMEMORY;

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

typedef _Ret_maybenull_ _Post_writable_byte_size_(dwSize) LPVOID WINAPI VIRTUALALLOC(
    _In_opt_    LPVOID  lpAddress,
    _In_        SIZE_T  dwSize,
    _In_        DWORD   flAllocationType,
    _In_        DWORD   flProtect
); // VirtualAlloc
typedef VIRTUALALLOC FAR* LPVIRTUALALLOC;

typedef _Ret_maybenull_ _Post_writable_byte_size_(dwSize) LPVOID WINAPI VIRTUALALLOCEX(
    _In_        HANDLE  hProcess,
    _In_opt_    LPVOID  lpAddress,
    _In_        SIZE_T  dwSize,
    _In_        DWORD   flAllocationType,
    _In_        DWORD   flProtect
); // VirtualAllocEx
typedef VIRTUALALLOCEX FAR* LPVIRTUALALLOCEX;

typedef
_When_(((dwFreeType& (MEM_RELEASE | MEM_DECOMMIT))) == (MEM_RELEASE | MEM_DECOMMIT),
    __drv_reportError("Passing both MEM_RELEASE and MEM_DECOMMIT to VirtualFree is not allowed. This results in the failure of this call"))

_When_(dwFreeType == 0,
    __drv_reportError("Passing zero as the dwFreeType parameter to VirtualFree is not allowed. This results in the failure of this call"))

_When_(((dwFreeType& MEM_RELEASE)) != 0 && dwSize != 0,
    __drv_reportError("Passing MEM_RELEASE and a non-zero dwSize parameter to VirtualFree is not allowed. This results in the failure of this call"))

_When_(((dwFreeType& MEM_DECOMMIT)) != 0,
    __drv_reportError("Calling VirtualFreeEx without the MEM_RELEASE flag frees memory but not address descriptors (VADs); results in address space leaks"))

_Success_(return != FALSE) BOOL WINAPI VIRTUALFREEEX(
    _In_                                                                                                                                        HANDLE  hProcess,
    _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID  lpAddress,
    _In_                                                                                                                                        SIZE_T  dwSize,
    _In_                                                                                                                                        DWORD   dwFreeType
); // VirtualFreeEx
typedef VIRTUALFREEEX FAR* LPVIRTUALFREEEX;

typedef _Success_(return != FALSE) BOOL WINAPI WRITEPROCESSMEMORY(
    _In_                    HANDLE  hProcess,
    _In_                    LPVOID  lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_                    SIZE_T  nSize,
    _Out_opt_               SIZE_T* lpNumberOfBytesWritten
); // WriteProcessMemory
typedef WRITEPROCESSMEMORY FAR* LPWRITEPROCESSMEMORY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS NTAPI RTLCREATEUSERTHREAD(
    _In_        HANDLE                  ProcessHandle,
    _In_opt_    PSECURITY_DESCRIPTOR    SecurityDescriptor,
    _In_        BOOLEAN                 CreateSuspended,
    _In_opt_    ULONG                   StackZeroBits,
    _In_opt_    SIZE_T                  StackReserve,
    _In_opt_    SIZE_T                  StackCommit,
    _In_        PTHREAD_START_ROUTINE   StartAddress,
    _In_opt_    PVOID                   Parameter,
    _Out_opt_   PHANDLE                 ThreadHandle,
    _Out_opt_   PCLIENT_ID              ClientId
); // RtlCreateUserThread
typedef RTLCREATEUSERTHREAD FAR* LPRTLCREATEUSERTHREAD;

typedef DWORD RTLNTSTATUSTODOSERROR(
    NTSTATUS Status
); // RtlNtStatusToDosError
typedef RTLNTSTATUSTODOSERROR FAR* LPRTLNTSTATUSTODOSERROR;

typedef DWORD WINAPI WAITFORSINGLEOBJECT(
    _In_ HANDLE hHandle,
    _In_ DWORD  dwMilliseconds
); // WaitForSingleObject
typedef WAITFORSINGLEOBJECT FAR* LPWAITFORSINGLEOBJECT;

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

typedef HANDLE WINAPI CREATEFILEW(
    _In_        LPCWSTR                 lpFileName,
    _In_        DWORD                   dwDesiredAccess,
    _In_        DWORD                   dwShareMode,
    _In_opt_    LPSECURITY_ATTRIBUTES   lpSecurityAttributes,
    _In_        DWORD                   dwCreationDisposition,
    _In_        DWORD                   dwFlagsAndAttributes,
    _In_opt_    HANDLE                  hTemplateFile
); // CreateFileW
typedef CREATEFILEW FAR* LPCREATEFILEW;

typedef DWORD WINAPI GETFILESIZE(
    _In_        HANDLE  hFile,
    _Out_opt_   LPDWORD lpFileSizeHigh
); // GetFileSize
typedef GETFILESIZE FAR* LPGETFILESIZE;

typedef _Must_inspect_result_ BOOL WINAPI READFILE(
    _In_                                                                                            HANDLE          hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE)   LPVOID          lpBuffer,
    _In_                                                                                            DWORD           nNumberOfBytesToRead,
    _Out_opt_                                                                                       LPDWORD         lpNumberOfBytesRead,
    _Inout_opt_                                                                                     LPOVERLAPPED    lpOverlapped
); // ReadFile
typedef READFILE FAR* LPREADFILE;

typedef _Success_(return == 0) _Ret_maybenull_ HLOCAL WINAPI LOCALFREE(
    _Frees_ptr_opt_ HLOCAL hMem
); // LocalFree
typedef LOCALFREE FAR* LPLOCALFREE;

inline LPGETPROCADDRESS pGetProcAddress;
inline LPGETMODULEHANDLEW pGetModuleHandleW;
inline LPLOADLIBRARYA pLoadLibraryA;
inline LPGETLASTERROR pGetLastError;
inline LPSETLASTERROR pSetLastError;
inline LPFORMATMESSAGEW pFormatMessageW;
inline LPRTLZEROMEMORY pRtlZeroMemory;
inline LPOPENPROCESS pOpenProcess;
inline LPCLOSEHANDLE pCloseHandle;
inline LPVIRTUALALLOC pVirtualAlloc;
inline LPVIRTUALALLOCEX pVirtualAllocEx;
inline LPVIRTUALFREEEX pVirtualFreeEx;
inline LPWRITEPROCESSMEMORY pWriteProcessMemory;
inline LPRTLCREATEUSERTHREAD pRtlCreateUserThread;
inline LPRTLNTSTATUSTODOSERROR pRtlNtStatusToDosError;
inline LPWAITFORSINGLEOBJECT pWaitForSingleObject;
inline LPCREATETOOLHELP32SNAPSHOT pCreateToolhelp32Snapshot;
inline LPPROCESS32FIRSTW pProcess32FirstW;
inline LPPROCESS32NEXTW pProcess32NextW;
inline LPCREATEFILEW pCreateFileW;
inline LPGETFILESIZE pGetFileSize;
inline LPREADFILE pReadFile;
inline LPLOCALFREE pLocalFree;

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