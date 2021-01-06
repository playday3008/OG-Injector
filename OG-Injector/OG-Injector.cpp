#include "OG-Injector.hpp"

#include "JunkDef.hpp"

// Don't change this!
#define _JUNK_BLOCK(s) __asm jmp s JUNKS __asm s:
#define A_JUNK_BLOCK(B, F) F(LABEL##B)
#define B_JUNK_BLOCK(C, F) A_JUNK_BLOCK(C, F)
#define JUNK B_JUNK_BLOCK(__COUNTER__, _JUNK_BLOCK)

using namespace std;

// Process name
#define PROCESS L"csgo.exe"

//#define OSIRIS
//#define GOESP
//#define BETA

#if (defined(OSIRIS) || defined(GOESP))
__forceinline void checkinst(array<bool, 3>& inst)
{
	JUNK;
	array<int, 4> CPUInfo{};
	JUNK;
	__cpuid(CPUInfo.data(), 0);
	JUNK;
	auto nIds = CPUInfo.at(0);

	JUNK;
	//  Detect Features
	if (nIds >= 0x00000001) {
		JUNK;
		__cpuid(CPUInfo.data(), 0x00000001);
		JUNK;
		inst.at(0) = (CPUInfo.at(3) & (1 << 26)) != 0;
		JUNK;
		inst.at(1) = (CPUInfo.at(2) & (1 << 28)) != 0;
		JUNK;
	}
	JUNK;
	if (nIds >= 0x00000007) {
		JUNK;
		__cpuid(CPUInfo.data(), 0x00000007);
		JUNK;
		inst.at(2) = (CPUInfo.at(1) & (1 << 5)) != 0;
		JUNK;
	}
	JUNK;
	return;
};
#endif

__forceinline bool bypass(DWORD dwProcess)
{
	// Restore original NtOpenFile from external process
	//credits: Daniel Krupiñski(pozdro dla ciebie byczku <3)
	JUNK;
	auto csgoProcessHandle = pOpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcess);
	JUNK;
	if (!csgoProcessHandle) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't open csgo.exe to bypass LoadLibrary injection") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return false;
		JUNK;
	}
	JUNK;
	auto ntdll = pLoadLibraryW(xorstr_(L"ntdll"));
	JUNK;
	if (!ntdll) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't load ntdll.dll module") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return false;
		JUNK;
	}
	JUNK;
	auto ntOpenFile = pGetProcAddress(ntdll, xorstr_("NtOpenFile"));

	if (ntOpenFile) {
		JUNK;
		array<char, 5> originalBytes{};
		JUNK;
		if (memcpy_s(originalBytes.data(), originalBytes.size(), ntOpenFile, 5)) {
			JUNK;
			_wsystem(xorstr_(L"Color 0C"));
			JUNK;
			wcout << xorstr_(L"Can't copy original NtOpenFile bytes to buffer") << endl;
			JUNK;
			_wsystem(xorstr_(L"pause"));
			JUNK;
			return false;
			JUNK;
		}
		if (!pWriteProcessMemory(csgoProcessHandle, ntOpenFile, originalBytes.data(), 5, NULL)) {
			JUNK;
			_wsystem(xorstr_(L"Color 0C"));
			JUNK;
			wcout << xorstr_(L"Can't write original NtOpenFile bytes to csgo.exe") << endl;
			JUNK;
			_wsystem(xorstr_(L"pause"));
			JUNK;
			return false;
			JUNK;
		}
		if (!pCloseHandle(csgoProcessHandle)) {
			JUNK;
			_wsystem(xorstr_(L"Color 0C"));
			JUNK;
			wcout << xorstr_(L"Can't close csgo.exe bypass handle") << endl;
			JUNK;
			_wsystem(xorstr_(L"pause"));
			JUNK;
			return false;
			JUNK;
		}
		JUNK;
		return true;
		JUNK;
	}
	else {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't find NtOpenFile into ntdll.dll") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return false;
		JUNK;
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

	JUNK;
	wcout << xorstr_(L"   ____       _      _         __   __________  ___________ ____ ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0A"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"  / __ \\_____(_)____(_)____   / /  / ____/ __ \\/ ____/ ___// __ \\") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0B"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L" / / / / ___/ / ___/ / ___/  / /  / / __/ / / / __/  \\__ \\/ /_/ /") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0C"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"/ /_/ (__  ) / /  / (__  )  / /  / /_/ / /_/ / /___ ___/ / ____/ ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0D"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"\\____/____/_/_/  /_/____/  / /   \\____/\\____/_____//____/_/      ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0E"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"    ____  __            __///                                    ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0F"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"   / __ \\/ /___ ___  __/ __ \\____ ___  __                        ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0A"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"  / /_/ / / __ `/ / / / / / / __ `/ / / /                        ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0B"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L" / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /                         ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0C"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"/_/   /_/\\__,_/\\__, /_____/\\__,_/\\__, /                          ") << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0D"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	wcout << xorstr_(L"              /____/            /____/                           ") << endl << endl;
	JUNK;
	_wsystem(xorstr_(L"Color 0E"));
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	_wsystem(xorstr_(L"Color 0F"));
	JUNK;
	wcout << xorstr_(L"Build: " __DATE__ ", " __TIME__ "") << endl << endl;
	JUNK;
	this_thread::sleep_for(chrono::milliseconds(50));
	JUNK;
	_wsystem(xorstr_(L"Color 07"));

#pragma endregion

#pragma region WinAPI

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
	pSetProcessMitigationPolicy = DynamicLoad<LPSETPROCESSMITIGATIONPOLICY>(kernel32, xorstr_("SetProcessMitigationPolicy"));
	JUNK;
	if (pSetProcessMitigationPolicy) {
		JUNK;
		// Disable injecting non microsoft libraries
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp{};
		JUNK;
		sp.MicrosoftSignedOnly = 1;
		JUNK;
		pSetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));
		JUNK;
	}

	JUNK;
	pLoadLibraryW = DynamicLoad<LPLOADLIBRARYW>(kernel32, xorstr_("LoadLibraryW"));

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
	if (!pGetProcAddress			|| !pGetModuleHandleW	||
		!pLoadLibraryW				|| !pOpenProcess		||
		!pCloseHandle				|| !pVirtualAllocEx		||
		!pWriteProcessMemory		|| !pCreateRemoteThread ||
		!pCreateToolhelp32Snapshot	|| !pProcess32FirstW	||
		!pProcess32NextW)
	{
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't load needed modules to correctly inject dll into process") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}

#pragma endregion

	#if (defined(OSIRIS) || defined(GOESP))
	// Get processor instructions
	JUNK;
	array<bool, 3> inst{};
	JUNK;
	checkinst(inst);
	#endif

#pragma region Osiris and GOESP part

#ifdef OSIRIS
	JUNK;
	wstring dllname = xorstr_(L"Osiris");
	JUNK;
#elif defined(GOESP)
	JUNK;
	wstring dllname = xorstr_(L"GOESP");
	JUNK;
#else
	JUNK;
	wstring dllname = xorstr_(L"library.dll");
	JUNK;
#endif

#if (defined(OSIRIS) || defined(GOESP)) && defined(BETA)
	JUNK;
	dllname += xorstr_(L"_BETA");
	JUNK;
#endif

#if (defined(OSIRIS) || defined(GOESP))
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
		wcout << xorstr_(L"DLL: ") << dllname << xorstr_(L" found") << endl;
	else {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't find: ") << dllname << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}

#pragma endregion

#pragma region Find process

	JUNK;
	wstring processName = xorstr_(PROCESS);
	JUNK;
	wcout << xorstr_(L"Finding ") << processName << xorstr_(L" process") << endl;

	JUNK;
	DWORD processId = NULL;
	JUNK;
	PROCESSENTRY32W entry{ sizeof(entry) };

	JUNK;
	auto snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	JUNK;
	if (pProcess32FirstW(snapshot, &entry))
		do {
			JUNK;
			if (wstring(entry.szExeFile) == processName)
				processId = entry.th32ProcessID;
			JUNK;
		} while (pProcess32NextW(snapshot, &entry));

	JUNK;
	if (!processId) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't find: ") << processName << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	};

	if (!pCloseHandle(snapshot)) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't close ") << processName << xorstr_(L" finder handle") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}

	JUNK;
	wcout << xorstr_(L"Process: ") << processName << xorstr_(L" found with PID: ") << dec << processId << endl;

#pragma endregion

	JUNK;
	// Bypass LoadLibrary injection for csgo
	if (!bypass(processId))
		return EXIT_FAILURE;

#pragma region Injection code

	JUNK;
	wstring dllPath = filesystem::absolute(dllname);
	JUNK;
	std::vector<wchar_t> dll(MAX_PATH);
	JUNK;
	dllPath.copy(dll.data(), dllPath.size() + 1);
	JUNK;
	dll.at(dllPath.size()) = '\0';

	JUNK;
	wcout << xorstr_(L"Injecting ") << dllname << xorstr_(L" into ") << processName << endl;

	JUNK;
	auto hProcess = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
	JUNK;
	if (!hProcess) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't open ") << processName << xorstr_(L" to write") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}
	JUNK;
	auto allocatedMem = pVirtualAllocEx(hProcess, NULL, dll.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	JUNK;
	if (!allocatedMem) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't allocate memory in ") << processName << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}
	JUNK;
	if (!pWriteProcessMemory(hProcess, allocatedMem, dll.data(), dll.size(), NULL)) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't write dll path to ") << processName << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}
	JUNK;
	auto thread = pCreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), allocatedMem, 0, 0);
	JUNK;
	if (!thread) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't create remote thread with LoadLibrary module in ") << processName << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}
	JUNK;
	if (!pCloseHandle(hProcess)) {
		JUNK;
		_wsystem(xorstr_(L"Color 0C"));
		JUNK;
		wcout << xorstr_(L"Can't close ") << processName << xorstr_(L"handle") << endl;
		JUNK;
		_wsystem(xorstr_(L"pause"));
		JUNK;
		return EXIT_FAILURE;
		JUNK;
	}

#pragma endregion

	JUNK;
	_wsystem(xorstr_(L"Color 0A"));
	JUNK;
	wcout << xorstr_(L"Successfully injected ") << dllname << xorstr_(L" into ") << processName << endl;
	JUNK;
	wcout << xorstr_(L"You have 5 seconds to read this information, GOODBYE") << endl;
	JUNK;
	this_thread::sleep_for(chrono::seconds(5));

	return EXIT_SUCCESS;
}
