﻿#include "OG-Injector.hpp"

using namespace std;

// Process name
#define PROCESS L"csgo.exe"

//#define OSIRIS
//#define GOESP
//#define BETA

#if (defined(OSIRIS) || defined(GOESP))
__forceinline void checkinst(array<bool, 3>& inst)
{
	array<int, 4> CPUInfo{};
	__cpuid(CPUInfo.data(), 0);
	auto nIds = CPUInfo.at(0);

	//  Detect Features
	if (nIds >= 0x00000001) {
		__cpuid(CPUInfo.data(), 0x00000001);
		inst.at(0) = (CPUInfo.at(3) & (1 << 26)) != 0;
		inst.at(1) = (CPUInfo.at(2) & (1 << 28)) != 0;
	}
	if (nIds >= 0x00000007) {
		__cpuid(CPUInfo.data(), 0x00000007);
		inst.at(2) = (CPUInfo.at(1) & (1 << 5)) != 0;
	}
	return;
};
#endif

__forceinline bool bypass(DWORD dwProcess)
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
		_wsystem(xorstr_(L"pause"));
		return false;
	}
	auto ntdll = pLoadLibraryW(xorstr_(L"ntdll"));
	if (!ntdll) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't load ntdll.dll module") << 
			termcolor::reset << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return false;
	}
	auto ntOpenFile = pGetProcAddress(ntdll, xorstr_("NtOpenFile"));

	if (ntOpenFile) {
		array<char, 5> originalBytes{};
		if (memcpy_s(originalBytes.data(), originalBytes.size(), ntOpenFile, 5)) {
			wcout << 
				termcolor::red << 
				xorstr_(L"Can't copy original NtOpenFile bytes to buffer") << 
				termcolor::reset << 
				endl;
			_wsystem(xorstr_(L"pause"));
			return false;
		}
		if (!pWriteProcessMemory(csgoProcessHandle, ntOpenFile, originalBytes.data(), 5, NULL)) {
			wcout << 
				termcolor::red << 
				xorstr_(L"Can't write original NtOpenFile bytes to csgo.exe") << 
				termcolor::reset << 
				endl;
			_wsystem(xorstr_(L"pause"));
			return false;
		}
		if (!pCloseHandle(csgoProcessHandle)) {
			wcout << 
				termcolor::red << 
				xorstr_(L"Can't close csgo.exe bypass handle") << 
				termcolor::reset << 
				endl;
			_wsystem(xorstr_(L"pause"));
			return false;
		}
		return true;
	}
	else {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't find NtOpenFile into ntdll.dll") << 
			termcolor::reset << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return false;
	}
};

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
		xorstr_(L"Build: " __DATE__ ", " __TIME__) << 
		termcolor::reset << 
		endl << endl;
	this_thread::sleep_for(chrono::milliseconds(50));

	#pragma endregion

	#pragma region WinAPI

	pGetProcAddress = GetProcAddress;
	pGetModuleHandleW = GetModuleHandleW;
	auto kernel32 = pGetModuleHandleW(xorstr_(L"kernel32"));
	if (!kernel32)
		return EXIT_FAILURE;

	pSetProcessMitigationPolicy = DynamicLoad<LPSETPROCESSMITIGATIONPOLICY>(kernel32, xorstr_("SetProcessMitigationPolicy"));
	if (pSetProcessMitigationPolicy) {
		// Disable injecting non microsoft libraries
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp{};
		sp.MicrosoftSignedOnly = 1;
		pSetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));
	}

	pLoadLibraryW = DynamicLoad<LPLOADLIBRARYW>(kernel32, xorstr_("LoadLibraryW"));

	pOpenProcess = DynamicLoad<LPOPENPROCESS>(kernel32, xorstr_("OpenProcess"));
	pCloseHandle = DynamicLoad<LPCLOSEHANDLE>(kernel32, xorstr_("CloseHandle"));
	pVirtualAllocEx = DynamicLoad<LPVIRTUALALLOCEX>(kernel32, xorstr_("VirtualAllocEx"));
	pWriteProcessMemory = DynamicLoad<LPWRITEPROCESSMEMORY>(kernel32, xorstr_("WriteProcessMemory"));
	pCreateRemoteThread = DynamicLoad<LPCREATEREMOTETHREAD>(kernel32, xorstr_("CreateRemoteThread"));

	pCreateToolhelp32Snapshot = DynamicLoad<LPCREATETOOLHELP32SNAPSHOT>(kernel32, xorstr_("CreateToolhelp32Snapshot"));
	pProcess32FirstW = DynamicLoad<LPPROCESS32FIRSTW>(kernel32, xorstr_("Process32FirstW"));
	pProcess32NextW = DynamicLoad<LPPROCESS32NEXTW>(kernel32, xorstr_("Process32NextW"));

	if (!pGetProcAddress				|| !pGetModuleHandleW			||
		!pLoadLibraryW					|| !pOpenProcess				||
		!pCloseHandle					|| !pVirtualAllocEx				||
		!pWriteProcessMemory			|| !pCreateRemoteThread			||
		!pCreateToolhelp32Snapshot		|| !pProcess32FirstW			||
		!pProcess32NextW) 
	{
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't load needed modules to correctly inject dll into process") << 
			termcolor::reset << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}

	#pragma endregion

	#pragma region Osiris and GOESP part

	#ifdef OSIRIS
	wstring dllname = xorstr_(L"Osiris");
	#elif defined(GOESP)
	wstring dllname = xorstr_(L"GOESP");
	#else
	wstring dllname = xorstr_(L"library.dll");
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

	wstring processName = xorstr_(PROCESS);
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
	PROCESSENTRY32W entry{ sizeof(entry) };

	auto snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
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
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
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
	if (!bypass(processId))
		return EXIT_FAILURE;

	#pragma region Injection code

	wstring dllPath = filesystem::absolute(dllname);
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

	auto hProcess = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
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
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	auto allocatedMem = pVirtualAllocEx(hProcess, NULL, dll.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocatedMem) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't allocate memory in ") << 
			termcolor::bright_red <<
			processName << 
			termcolor::reset << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	if (!pWriteProcessMemory(hProcess, allocatedMem, dll.data(), dll.size(), NULL)) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't write dll path to ") << 
			termcolor::bright_red <<
			processName << 
			termcolor::reset << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	auto thread = pCreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), allocatedMem, 0, 0);
	if (!thread) {
		wcout << 
			termcolor::red << 
			xorstr_(L"Can't create remote thread with LoadLibrary module in ") << 
			termcolor::bright_red <<
			processName << 
			termcolor::reset << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
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
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
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
