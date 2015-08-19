// th145launch.cpp : 定义控制台应用程序的入口点。
//
#include "hook.h"
#include "eh.h"
#include <iostream>
#ifdef _DEBUG
// #include "dbghelp.h"
#endif
#define SINGLE_PROCESS 0

static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];
static CHAR s_szDllPath[MAX_PATH];
static bool s_exitProcess = false;
static bool s_debugger = false;
static FileMapObject* s_mapObj = nullptr;

static BOOL s_bLog = FALSE;
static LONG s_nTlsIndent = -1;
static LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;

void ReleaseMapObj()
{
	if (s_mapObj)
	{
		UnmapViewOfFile(s_mapObj);
		s_mapObj = nullptr;
	}
}

void OutputMessage(LPCSTR str)
{
	static HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOut && str && str[0] != 0)
	{
		DWORD writen = 0;
		if (!WriteFile(hOut, str, strlen(str) + 1, &writen, nullptr))
		{
// 			MessageBoxA(nullptr, "write handle failed", "hook", MB_OK);
		}
		//std::cout << str;
	}
}

BOOL __stdcall Mine_CreateProcessA(LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
#if SINGLE_PROCESS
	if (lpCommandLine && strlen(lpCommandLine) >= 3)
	{
		auto lpCmd = lpCommandLine;
		lpCmd += strlen(lpCmd) - 3;
		if (0 == strcmp(lpCmd, " -1"))
			return TRUE;
	}
#endif
	PROCESS_INFORMATION procInfo;
	if (lpProcessInformation == NULL) {
		lpProcessInformation = &procInfo;
		ZeroMemory(&procInfo, sizeof(procInfo));
	}

	STARTUPINFOA startupinfo = { 0 };
	startupinfo.cb = sizeof(STARTUPINFOA);
	startupinfo.dwFlags = STARTF_USESTDHANDLES;
	startupinfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	BOOL rv = 0;
	__try {
		OutputMessage("CreateProcessA\n");
		rv = DetourCreateProcessWithDllA(lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			TRUE,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			&startupinfo,
			lpProcessInformation,
			s_szDllPath,
			Real_CreateProcessA);
	}
	__finally {
	};
	return rv;
}

BOOL __stdcall Mine_CreateProcessW(LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	PROCESS_INFORMATION procInfo;
	if (lpProcessInformation == NULL) {
		lpProcessInformation = &procInfo;
		ZeroMemory(&procInfo, sizeof(procInfo));
	}

	BOOL rv = 0;
	__try {
		OutputMessage("CreateProcessW\n");
		rv = DetourCreateProcessWithDllW(lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation,
			s_szDllPath,
			Real_CreateProcessW);
	}
	__finally {
	};
	return rv;
}

BOOL __stdcall Mine_EnumProcessModules(
	HANDLE hProcess,
	HMODULE *lphModule,
	DWORD cb,
	LPDWORD lpcbNeeded)
{
	static int nCnt = 0;
	if (++nCnt > 2)
 		return Real_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);

	if (lpcbNeeded)
		*lpcbNeeded = sizeof(HMODULE);
	if (lphModule)
		*lphModule = GetModuleHandleA("user32");
	OutputMessage("EnumProcessModules\n");

	return TRUE;
}

BOOL __stdcall Mine_WaitForDebugEvent(
	_Out_ LPDEBUG_EVENT lpDebugEvent,
	_In_ DWORD dwMilliseconds)
{
	BOOL res = Real_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);
	if (lpDebugEvent)
	{
		static int exceptCount = 0;
		switch (lpDebugEvent->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			OutputMessage("EXCEPTION_DEBUG_EVENT\n");
			++exceptCount;
			if (exceptCount > 100)
				lpDebugEvent->dwDebugEventCode = 0;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			ReleaseMapObj();
			OutputMessage("#EXIT_PROCESS_DEBUG_EVENT\n");
			s_exitProcess = true;
			s_mapObj = nullptr;
			break;
		}
	}
	return res;
}

BOOL __stdcall Mine_TerminateProcess(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode)
{
	ReleaseMapObj();

	static char buf[256] = { 0 };
	sprintf_s(buf, "terminateProcess %d @%d",
		GetProcessId(hProcess),
		GetProcessId(GetCurrentProcess()));
#ifdef _DEBUG
	MessageBoxA(nullptr, buf, "hook", MB_OK);
#endif
	OutputMessage(buf);
	return Real_TerminateProcess(hProcess, uExitCode);
}

BOOL __stdcall Mine_IsDebuggerPresent()
{
	if (s_debugger)
		return FALSE;

	static UINT nCheckCnt = 0;
	++nCheckCnt;
	if (nCheckCnt == 3)
	{
		char buf[255] = { 0 };
		sprintf_s(buf, "TOKEN_%d", (int)GetCurrentProcess());
		HANDLE hFileMappintObj = OpenFileMappingA(0xF001Fu, FALSE, buf);
		s_mapObj = (FileMapObject*)Real_MapViewOfFile(hFileMappintObj, 0xF001F, 0, 0, 0);
#if SINGLE_PROCESS
		GetModuleFileNameA(GetModuleHandleA(nullptr), buf, 254);
		if (s_mapObj)
		{
 			s_mapObj->prevTime = Real_timeGetTime();
			s_mapObj->hWnd = CreateWindowExA(
				0, "STATIC", "hoke",
				0xCF0000u, 0, 0,
				128, 128, nullptr,
				nullptr, GetModuleHandleA(nullptr), 0);
			assert(s_mapObj->hWnd);
		}
#endif
	}
#if SINGLE_PROCESS
	if (nCheckCnt > 2)
		return TRUE;
	return FALSE;
#else
	return Real_IsDebuggerPresent();
#endif
}

HANDLE __stdcall Mine_CreateFileMappingA(
	_In_ HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_ DWORD flProtect,
	_In_ DWORD dwMaximumSizeHigh,
	_In_ DWORD dwMaximumSizeLow,
	_In_opt_ LPCSTR lpName)
{
	OutputMessage("CreateFileMappingA\n");
	return Real_CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

LPVOID __stdcall Mine_MapViewOfFile(
	_In_ HANDLE hFileMappingObject,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwFileOffsetHigh,
	_In_ DWORD dwFileOffsetLow,
	_In_ SIZE_T dwNumberOfBytesToMap)
{
	assert(hFileMappingObject);
	LPVOID pResult = Real_MapViewOfFile(
		hFileMappingObject,
		dwDesiredAccess, 
		dwFileOffsetHigh,
		dwFileOffsetLow,
		dwNumberOfBytesToMap);

	OutputMessage("MapViewOfFile\n");
	if (!s_mapObj)
	{
		s_mapObj = (FileMapObject*)pResult;
#if SINGLE_PROCESS
		if (s_mapObj)
		{
			s_mapObj->hWnd = CreateWindowExA(
				0, "STATIC", "hoke",
				0xCF0000u, 0, 0,
				128, 128, nullptr,
				nullptr, GetModuleHandleA(nullptr), 0);
			assert(s_mapObj->hWnd);
		}
#endif
	}
	assert(pResult);
	return pResult;
}

HWND __stdcall Mine_CreateWindowExA(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCSTR lpClassName,
	_In_opt_ LPCSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X, _In_ int Y,
	_In_ int nWidth, _In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam)
{
	OutputMessage("CreateWindowExA\n");
	HWND hWnd = Real_CreateWindowExA(dwExStyle, lpClassName,
		lpWindowName, dwStyle,
		X, Y, nWidth, nHeight,
		hWndParent, hMenu,
		hInstance, lpParam);
	assert(hWnd);

	return hWnd;
}

BOOL __stdcall Mine_IsWindow(_In_opt_ HWND hWnd)
{
#if SINGLE_PROCESS
// 	if (s_mapObj && s_mapObj->hWnd == hWnd)
// 		return TRUE;
#endif
	return Real_IsWindow(hWnd);
}

static bool bBeginCheckTime = false;
BOOL __stdcall Mine_IsHungAppWindow(_In_ HWND hwnd)
{
	bBeginCheckTime = true;
	if (s_exitProcess)
		return Real_IsHungAppWindow(hwnd);
	else
		return FALSE;
}

DWORD __stdcall Mine_timeGetTime()
{
	DWORD curTime = Real_timeGetTime();
	if (!bBeginCheckTime)
		return curTime;

	bBeginCheckTime = false;
	if (s_mapObj /*&& curTime - s_mapObj->prevTime <= 500*/)
	{
		s_mapObj->prevTime = curTime - 1;
	}
	return curTime;
}

BOOL __stdcall Mine_PostMessageA(_In_opt_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam)
{
	return Real_PostMessageA(hWnd, Msg, wParam, lParam);
}

DWORD __stdcall Mine_WaitForMultipleObjectsEx(
	_In_ DWORD nCount,
	_In_reads_(nCount) CONST HANDLE * lpHandles,
	_In_ BOOL bWaitAll,
	_In_ DWORD dwMilliseconds,
	_In_ BOOL bAlertable)
{
	DWORD res = Real_WaitForMultipleObjectsEx(nCount, lpHandles, bWaitAll, dwMilliseconds, bAlertable);

	return res;
}

VOID DetAttach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
	PVOID pvReal = NULL;
	if (ppvReal == NULL) {
		ppvReal = &pvReal;
	}

	static char buf[256] = { 0 };
	sprintf_s(buf, "Attach %s...\n", psz);
	OutputMessage(buf);

	LONG l = DetourAttach(ppvReal, pvMine);
	if (l != 0) {
		OutputMessage("Attach failed\n");

		// 		Decode((PBYTE)*ppvReal, 3);
	}
}

VOID DetDetach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
	LONG l = DetourDetach(ppvReal, pvMine);
	if (l != 0) {
#if 0
		Syelog(SYELOG_SEVERITY_NOTICE,
			"Detach failed: `%s': error %d\n", DetRealName(psz), l);
#else
		(void)psz;
#endif
	}
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

LONG AttachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// For this many APIs, we'll ignore one or two can't be detoured.
	DetourSetIgnoreTooSmall(TRUE);

	HMODULE hPsapi = GetModuleHandleA("psapi.dll");
	if (hPsapi)
	{
		typedef BOOL(__stdcall * FUNCTYPE)(
			HANDLE hProcess,
			HMODULE *lphModule,
			DWORD cb,
			LPDWORD lpcbNeeded);

		Real_EnumProcessModules = (FUNCTYPE)GetProcAddress(hPsapi, "EnumProcessModules");
		ATTACH(EnumProcessModules);
	}
	ATTACH(CreateProcessA);
	ATTACH(CreateProcessW);
#ifdef _DEBUG
	ATTACH(TerminateProcess);
// 	ATTACH(CreateFileMappingA);
// 	ATTACH(MapViewOfFile);
#endif
	if (s_debugger)
	{
		ATTACH(WaitForDebugEvent);
	}
	ATTACH(IsDebuggerPresent);
	ATTACH(IsHungAppWindow);
	ATTACH(timeGetTime);
#if SINGLE_PROCESS
// 	ATTACH(IsWindow);
// 	ATTACH(CreateWindowExA);
	ATTACH(WaitForMultipleObjectsEx);
#endif

	PVOID *ppbFailedPointer = NULL;
	LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
	if (error != 0) {
		printf("traceapi.dll: Attach transaction failed to commit. Error %d (%p/%p)",
			error, ppbFailedPointer, *ppbFailedPointer);
		return error;
	}
	return 0;
}

LONG DetachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// For this many APIs, we'll ignore one or two can't be detoured.
	DetourSetIgnoreTooSmall(TRUE);

	DETACH(CreateProcessA);
	DETACH(CreateProcessW);
	DETACH(EnumProcessModules);
#ifdef _DEBUG
	DETACH(TerminateProcess);
// 	DETACH(CreateFileMappingA);
// 	DETACH(MapViewOfFile);
#endif
	if (s_debugger)
	{
		DETACH(WaitForDebugEvent);
	}
	DETACH(IsDebuggerPresent);
	DETACH(IsHungAppWindow);
	DETACH(timeGetTime);
#if SINGLE_PROCESS
// 	DETACH(IsWindow);
// 	DETACH(CreateWindowExA);
	DETACH(WaitForMultipleObjectsEx);
#endif

	if (DetourTransactionCommit() != 0) {
		PVOID *ppbFailedPointer = NULL;
		LONG error = DetourTransactionCommitEx(&ppbFailedPointer);

		printf("traceapi.dll: Detach transaction failed to commit. Error %d (%p/%p)",
			error, ppbFailedPointer, *ppbFailedPointer);
		return error;
	}
	return 0;
}


//////////////////////////////////////////////////////////////////////////////
//
PIMAGE_NT_HEADERS NtHeadersForInstance(HINSTANCE hInst)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
	__try {
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
			pDosHeader->e_lfanew);
		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
			SetLastError(ERROR_INVALID_EXE_SIGNATURE);
			return NULL;
		}
		if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
			SetLastError(ERROR_EXE_MARKED_INVALID);
			return NULL;
		}
		return pNtHeader;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	}
	SetLastError(ERROR_EXE_MARKED_INVALID);

	return NULL;
}

BOOL InstanceEnumerate(HINSTANCE hInst)
{
	WCHAR wzDllName[MAX_PATH];

	PIMAGE_NT_HEADERS pinh = NtHeadersForInstance(hInst);
	if (pinh && GetModuleFileNameW(hInst, wzDllName, ARRAYSIZE(wzDllName))) {
		return TRUE;
	}
	return FALSE;
}

BOOL ProcessEnumerate()
{
	PBYTE pbNext;
	for (PBYTE pbRegion = (PBYTE)0x10000;; pbRegion = pbNext) {
		MEMORY_BASIC_INFORMATION mbi;
		ZeroMemory(&mbi, sizeof(mbi));

		if (VirtualQuery((PVOID)pbRegion, &mbi, sizeof(mbi)) <= 0) {
			break;
		}
		pbNext = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

		// Skip free regions, reserver regions, and guard pages.
		//
		if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE) {
			continue;
		}
		if (mbi.Protect & PAGE_GUARD || mbi.Protect & PAGE_NOCACHE) {
			continue;
		}
		if (mbi.Protect == PAGE_NOACCESS) {
			continue;
		}

		// Skip over regions from the same allocation...
		{
			MEMORY_BASIC_INFORMATION mbiStep;

			while (VirtualQuery((PVOID)pbNext, &mbiStep, sizeof(mbiStep)) > 0) {
				if ((PBYTE)mbiStep.AllocationBase != pbRegion) {
					break;
				}
				pbNext = (PBYTE)mbiStep.BaseAddress + mbiStep.RegionSize;
				mbi.Protect |= mbiStep.Protect;
			}
		}

		WCHAR wzDllName[MAX_PATH];
		PIMAGE_NT_HEADERS pinh = NtHeadersForInstance((HINSTANCE)pbRegion);

		if (pinh &&
			GetModuleFileNameW((HINSTANCE)pbRegion, wzDllName, ARRAYSIZE(wzDllName))) {
		}
		else {
		}
	}

	LPVOID lpvEnv = GetEnvironmentStrings();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
	(void)hDll;

	if (s_nTlsIndent >= 0) {
		TlsSetValue(s_nTlsIndent, (PVOID)0);
	}
	if (s_nTlsThread >= 0) {
		LONG nThread = InterlockedIncrement(&s_nThreadCnt);
		TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
	}
	return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
	(void)hDll;

	if (s_nTlsIndent >= 0) {
		TlsSetValue(s_nTlsIndent, (PVOID)0);
	}
	if (s_nTlsThread >= 0) {
		TlsSetValue(s_nTlsThread, (PVOID)0);
	}
	return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
	s_bLog = FALSE;
	s_nTlsIndent = TlsAlloc();
	s_nTlsThread = TlsAlloc();
	ThreadAttach(hDll);

	WCHAR wzExeName[MAX_PATH];

	s_hInst = hDll;
	GetModuleFileNameW(hDll, s_wzDllPath, ARRAYSIZE(s_wzDllPath));
	GetModuleFileNameW(NULL, wzExeName, ARRAYSIZE(wzExeName));
	sprintf_s(s_szDllPath, ARRAYSIZE(s_szDllPath), "%ls", s_wzDllPath);

	char sDirver[MAX_PATH];
	char sPath[MAX_PATH];
	char sName[MAX_PATH];
	char sExt[MAX_PATH];
	GetModuleFileNameA(GetModuleHandleA(NULL), s_szDllPath, ARRAYSIZE(s_szDllPath));
	_splitpath_s(s_szDllPath, sDirver, sPath, sName, sExt);
	sprintf_s(s_szDllPath, "%s%s\\th145hook.dll", sDirver, sPath);

	ProcessEnumerate();

	LONG error = AttachDetours();
	if (error != NO_ERROR) {
		OutputMessage("### Error attaching detours\n");
	}

	s_bLog = TRUE;
	return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
	ThreadDetach(hDll);
	s_bLog = FALSE;

	LONG error = DetachDetours();
	if (error != NO_ERROR) {
		OutputMessage("### Error detaching detours\n");
	}

	// 	Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
	// 	SyelogClose(FALSE);

	if (s_nTlsIndent >= 0) {
		TlsFree(s_nTlsIndent);
	}
	if (s_nTlsThread >= 0) {
		TlsFree(s_nTlsThread);
	}
	return TRUE;
}

LONG WINAPI OnUnhandledException(PEXCEPTION_POINTERS pExceptionPtrs)
{
	MessageBoxA(nullptr, "OnUnhandledException", "hook", 0);
	return EXCEPTION_EXECUTE_HANDLER;
}

void onTerminate()
{
	MessageBoxA(nullptr, "crt terminate", "hook", 0);
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
	(void)hModule;
	(void)lpReserved;
	BOOL ret;

	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	static bool bLoaded = false;
	if (!bLoaded)
	{
#ifdef _DEBUG
// 		assert(!"DllMain");
		MessageBoxA(nullptr, GetCommandLineA(), "hook", 0);
		SetUnhandledExceptionFilter(OnUnhandledException);
		set_terminate(onTerminate);
#endif
#if !SINGLE_PROCESS
		char buf[255] = { 0 };
		sprintf_s(buf, " %d", GetCurrentProcess());
		LPCSTR lpCmd = GetCommandLineA();
		if (lpCmd && strlen(lpCmd) >= 3)
		{
			lpCmd += strlen(lpCmd) - 3;
			if (0 == strcmp(lpCmd, buf))
				s_debugger = true;
		}
#endif
		bLoaded = true;
	}

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		OutputMessage("DllMain DLL_PROCESS_ATTACH\n");
		DetourRestoreAfterWith();
		return ProcessAttach(hModule);
	case DLL_PROCESS_DETACH:
		MessageBoxA(nullptr, GetCommandLineA(), "hook", 0);
		OutputMessage("#DllMain DLL_PROCESS_DETACH\n");
		ReleaseMapObj();
		ret = ProcessDetach(hModule);
		return ret;
	case DLL_THREAD_ATTACH:
// 		OutputMessage("DllMain DLL_THREAD_ATTACH\n");
		return ThreadAttach(hModule);
	case DLL_THREAD_DETACH:
// 		OutputMessage("DllMain DLL_THREAD_DETACH\n");
		return ThreadDetach(hModule);
	}
	return TRUE;
}

__declspec(dllexport) int __stdcall dummy()
{
	return 0;
}
