#include "OG-Injector.hpp"

using namespace std;

// Process name
#define PROCESS L"csgo.exe"

//#define OSIRIS
//#define GOESP
//#define BETA

// Terminal colored output
#define RESET   L"\033[0m"
#define BLACK   L"\033[30m"      /* Black */
#define RED     L"\033[31m"      /* Red */
#define GREEN   L"\033[32m"      /* Green */
#define YELLOW  L"\033[33m"      /* Yellow */
#define BLUE    L"\033[34m"      /* Blue */
#define MAGENTA L"\033[35m"      /* Magenta */
#define CYAN    L"\033[36m"      /* Cyan */
#define WHITE   L"\033[37m"      /* White */
#define BOLD	L"\033[1m"       /* Bold */

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
			xorstr_(RED) << 
			xorstr_(L"Can't open csgo.exe to bypass LoadLibrary injection") << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return false;
	}
	auto ntdll = pLoadLibraryW(xorstr_(L"ntdll"));
	if (!ntdll) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't load ntdll.dll module") << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return false;
	}
	auto ntOpenFile = pGetProcAddress(ntdll, xorstr_("NtOpenFile"));

	if (ntOpenFile) {
		array<char, 5> originalBytes{};
		if (memcpy_s(originalBytes.data(), originalBytes.size(), ntOpenFile, 5)) {
			wcout << 
				xorstr_(RED) << 
				xorstr_(L"Can't copy original NtOpenFile bytes to buffer") << 
				xorstr_(RESET) << 
				endl;
			_wsystem(xorstr_(L"pause"));
			return false;
		}
		if (!pWriteProcessMemory(csgoProcessHandle, ntOpenFile, originalBytes.data(), 5, NULL)) {
			wcout << 
				xorstr_(RED) << 
				xorstr_(L"Can't write original NtOpenFile bytes to csgo.exe") << 
				xorstr_(RESET) << 
				endl;
			_wsystem(xorstr_(L"pause"));
			return false;
		}
		if (!pCloseHandle(csgoProcessHandle)) {
			wcout << 
				xorstr_(RED) << 
				xorstr_(L"Can't close csgo.exe bypass handle") << 
				xorstr_(RESET) << 
				endl;
			_wsystem(xorstr_(L"pause"));
			return false;
		}
		return true;
	}
	else {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't find NtOpenFile into ntdll.dll") << 
			xorstr_(RESET) << 
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

	wcout << xorstr_(RED) << xorstr_(L"   ____       _      _         __   __________  ___________ ____ ") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(GREEN) << xorstr_(L"  / __ \\_____(_)____(_)____   / /  / ____/ __ \\/ ____/ ___// __ \\") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(YELLOW) << xorstr_(L" / / / / ___/ / ___/ / ___/  / /  / / __/ / / / __/  \\__ \\/ /_/ /") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(BLUE) << xorstr_(L"/ /_/ (__  ) / /  / (__  )  / /  / /_/ / /_/ / /___ ___/ / ____/ ") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(MAGENTA) << xorstr_(L"\\____/____/_/_/  /_/____/  / /   \\____/\\____/_____//____/_/") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(CYAN) << xorstr_(L"    ____  __            __///") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(RED) << xorstr_(L"   / __ \\/ /___ ___  __/ __ \\____ ___  __") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(GREEN) << xorstr_(L"  / /_/ / / __ `/ / / / / / / __ `/ / / /") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(YELLOW) << xorstr_(L" / ____/ / /_/ / /_/ / /_/ / /_/ / /_/ /") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(BLUE) << xorstr_(L"/_/   /_/\\__,_/\\__, /_____/\\__,_/\\__, /") << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << xorstr_(MAGENTA) << xorstr_(L"              /____/            /____/") << endl << endl;
	this_thread::sleep_for(chrono::milliseconds(50));
	wcout << 
		xorstr_(BOLD) << 
		xorstr_(WHITE) << 
		xorstr_(L"Build: " __DATE__ ", " __TIME__) << 
		xorstr_(RESET) << 
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
			xorstr_(RED) << 
			xorstr_(L"Can't load needed modules to correctly inject dll into process") << 
			xorstr_(RESET) << 
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
		xorstr_(GREEN) <<
		xorstr_(L"DLL: ") <<
		xorstr_(BOLD) <<
		dllname <<
		xorstr_(RESET) <<
		xorstr_(GREEN) <<
		xorstr_(L" found") <<
		xorstr_(RESET) <<
		endl;
	else {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't find: ") << 
			xorstr_(BOLD) << 
			dllname << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}

	#pragma endregion

	#pragma region Find process

	wstring processName = xorstr_(PROCESS);
	wcout <<
		xorstr_(YELLOW) <<
		xorstr_(L"Finding ") <<
		xorstr_(BOLD) <<
		processName <<
		xorstr_(RESET) <<
		xorstr_(YELLOW) <<
		xorstr_(L" process") <<
		xorstr_(RESET) <<
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
			xorstr_(RED) << 
			xorstr_(L"Can't find: ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}

	if (!pCloseHandle(snapshot)) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't close ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			xorstr_(RED) << 
			xorstr_(L" finder handle") << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}

	wcout <<
		xorstr_(GREEN) <<
		xorstr_(L"Process: ") <<
		xorstr_(BOLD) <<
		processName <<
		xorstr_(RESET) <<
		xorstr_(GREEN) <<
		xorstr_(L" found with PID: ") <<
		xorstr_(BOLD) <<
		dec << processId <<
		xorstr_(RESET) <<
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
		xorstr_(YELLOW) <<
		xorstr_(L"Injecting ") <<
		xorstr_(BOLD) <<
		dllname <<
		xorstr_(RESET) <<
		xorstr_(YELLOW) <<
		xorstr_(L" into ") <<
		xorstr_(BOLD) <<
		processName <<
		xorstr_(RESET) <<
		endl;

	auto hProcess = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);
	if (!hProcess) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't open ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			xorstr_(RED) << 
			xorstr_(L" to write") <<
			xorstr_(RESET) <<
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	auto allocatedMem = pVirtualAllocEx(hProcess, NULL, dll.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocatedMem) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't allocate memory in ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	if (!pWriteProcessMemory(hProcess, allocatedMem, dll.data(), dll.size(), NULL)) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't write dll path to ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	auto thread = pCreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), allocatedMem, 0, 0);
	if (!thread) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't create remote thread with LoadLibrary module in ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}
	if (!pCloseHandle(hProcess)) {
		wcout << 
			xorstr_(RED) << 
			xorstr_(L"Can't close ") << 
			xorstr_(BOLD) << 
			processName << 
			xorstr_(RESET) << 
			xorstr_(RED) << 
			xorstr_(L"handle") << 
			xorstr_(RESET) << 
			endl;
		_wsystem(xorstr_(L"pause"));
		return EXIT_FAILURE;
	}

	#pragma endregion

	wcout <<
		xorstr_(GREEN) <<
		xorstr_(L"Successfully injected ") <<
		xorstr_(BOLD) <<
		xorstr_(CYAN) <<
		dllname <<
		xorstr_(RESET) <<
		xorstr_(YELLOW) <<
		xorstr_(L" into ") <<
		xorstr_(BOLD) <<
		xorstr_(RED) <<
		processName <<
		xorstr_(RESET) <<
		endl;
	wcout <<
		xorstr_(BOLD) <<
		xorstr_(WHITE) <<
		xorstr_(L"You have 5 seconds to read this information, GOODBYE") <<
		xorstr_(RESET) <<
		endl;
	this_thread::sleep_for(chrono::seconds(5));

	return EXIT_SUCCESS;
}
