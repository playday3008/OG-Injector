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
	array<int, 4> CPUInfo{};
	__cpuid(CPUInfo.data(), 0);
	const auto nIds = CPUInfo.at(0);

	//  Detect Features
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

int ErrorExit(const wstring& lpszFunction)
{
	// Retrieve the system error message for the last-error code
	if (!(pGetLastError && pFormatMessageW))
		return EXIT_FAILURE;

	const DWORD dw = pGetLastError();

	if (!dw)
		wcout << xorstr_(L"GetLastError() didn't catch anything") << endl;
	else {
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

		wcout << xorstr_("GetLastError() catched error:") << endl <<
			lpszFunction <<
			xorstr_(L" failed with error ") <<
			to_wstring(dw) <<
			xorstr_(L": ") <<
			lpMsgBuf <<
			endl;

		LocalFree(lpMsgBuf);
	}

	_wsystem(xorstr_(L"pause"));

	exit(dw);
}

inline int bypass(const DWORD dwProcess)
{
	// Restore original NtOpenFile from external process
	//credits: Daniel Krupiñski(pozdro dla ciebie byczku <3)
	auto csgoProcessHandle = pOpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);
	if (!csgoProcessHandle) {
		wcout <<
			termcolor::red <<
			xorstr_(L"Can't open csgo.exe to bypass LoadLibrary injection") <<
			termcolor::reset <<
			endl;
		return ErrorExit(xorstr_(L"OpenProcess"));
	}
	auto ntdll = pLoadLibraryW(xorstr_(L"ntdll"));
	if (!ntdll) {
		wcout <<
			termcolor::red <<
			xorstr_(L"Can't load ntdll.dll module") <<
			termcolor::reset <<
			endl;
		return ErrorExit(xorstr_(L"LoadLibraryW"));
	}

	if (auto ntOpenFile = pGetProcAddress(ntdll, xorstr_("NtOpenFile"));
		ntOpenFile) {
		array<char, 5> originalBytes{};
		if (memcpy_s(originalBytes.data(), originalBytes.size(), ntOpenFile, 5)) {
			wcout <<
				termcolor::red <<
				xorstr_(L"Can't copy original NtOpenFile bytes to buffer") <<
				termcolor::reset <<
				endl;
			return ErrorExit(xorstr_(L"memcpy_s"));
		}
		if (!pWriteProcessMemory(csgoProcessHandle, ntOpenFile, originalBytes.data(), 5, nullptr)) {
			wcout <<
				termcolor::red <<
				xorstr_(L"Can't write original NtOpenFile bytes to csgo.exe") <<
				termcolor::reset <<
				endl;
			return ErrorExit(xorstr_(L"WriteProcessMemory"));
		}
		if (!pCloseHandle(csgoProcessHandle)) {
			wcout <<
				termcolor::red <<
				xorstr_(L"Can't close csgo.exe bypass handle") <<
				termcolor::reset <<
				endl;
			return ErrorExit(xorstr_(L"CloseHandle"));
		}
		return EXIT_SUCCESS;
	}
	wcout <<
		termcolor::red <<
		xorstr_(L"Can't get NtOpenFile from ntdll.dll") <<
		termcolor::reset <<
		endl;
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

	pLoadLibraryW = DynamicLoad<LPLOADLIBRARYW>(kernel32, xorstr_("LoadLibraryW"));
	pGetLastError = DynamicLoad<LPGETLASTERROR>(kernel32, xorstr_("GetLastError"));
	pFormatMessageW = DynamicLoad<LPFORMATMESSAGEW>(kernel32, xorstr_("FormatMessageW"));

	pOpenProcess = DynamicLoad<LPOPENPROCESS>(kernel32, xorstr_("OpenProcess"));
	pCloseHandle = DynamicLoad<LPCLOSEHANDLE>(kernel32, xorstr_("CloseHandle"));
	pVirtualAllocEx = DynamicLoad<LPVIRTUALALLOCEX>(kernel32, xorstr_("VirtualAllocEx"));
	pWriteProcessMemory = DynamicLoad<LPWRITEPROCESSMEMORY>(kernel32, xorstr_("WriteProcessMemory"));
	pCreateRemoteThread = DynamicLoad<LPCREATEREMOTETHREAD>(kernel32, xorstr_("CreateRemoteThread"));

	pCreateToolhelp32Snapshot = DynamicLoad<LPCREATETOOLHELP32SNAPSHOT>(kernel32, xorstr_("CreateToolhelp32Snapshot"));
	pProcess32FirstW = DynamicLoad<LPPROCESS32FIRSTW>(kernel32, xorstr_("Process32FirstW"));
	pProcess32NextW = DynamicLoad<LPPROCESS32NEXTW>(kernel32, xorstr_("Process32NextW"));

	if (!pGetProcAddress				|| !pGetModuleHandleW			||
		!pLoadLibraryW					|| !pGetLastError				||
		!pFormatMessageW				|| !pOpenProcess				||
		!pCloseHandle					|| !pVirtualAllocEx				||
		!pWriteProcessMemory			|| !pCreateRemoteThread			||
		!pCreateToolhelp32Snapshot		|| !pProcess32FirstW			||
		!pProcess32NextW) 
	{
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't load needed functions to correct dll injection into process") << 
			termcolor::reset << 
			endl;
		return ErrorExit(xorstr_(L"DynamicLoad"));
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
		return ErrorExit(xorstr_(L"CreateToolhelp32Snapshot"));
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
		return ErrorExit(xorstr_(L"CloseHandle"));
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

	// Bypass LoadLibrary injection for csgo
	if (bypass(processId) != EXIT_SUCCESS)
		return EXIT_FAILURE;

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

	auto* hProcess = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
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
		return ErrorExit(xorstr_(L"OpenProcess"));
	}
	auto* allocatedMem = pVirtualAllocEx(hProcess, nullptr, dll.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocatedMem) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't allocate memory in ") << 
			termcolor::bright_red <<
			processName << 
			termcolor::reset << 
			endl;
		return ErrorExit(xorstr_(L"VirtualAllocEx"));
	}
	if (!pWriteProcessMemory(hProcess, allocatedMem, dll.data(), dll.size(), nullptr)) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't write dll path to ") << 
			termcolor::bright_red <<
			processName << 
			termcolor::reset << 
			endl;
		return ErrorExit(xorstr_(L"WriteProcessMemory"));
	}
	auto* thread = pCreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), allocatedMem, 0, nullptr);
	if (!thread) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't create remote thread with LoadLibrary module in ") << 
			termcolor::bright_red <<
			processName << 
			termcolor::reset << 
			endl;
		return ErrorExit(xorstr_(L"CreateRemoteThread"));
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
		return ErrorExit(xorstr_(L"CloseHandle"));
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
