#pragma once

#if _MSC_VER >= 1300
#include <winsock2.h>
#endif
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <detours.h>
#include <cassert>

struct FileMapObject
{
	UINT curTime;
	UINT gamePID;
	UINT prevTime;
	HWND hWnd;
};

BOOL ProcessEnumerate();
BOOL InstanceEnumerate(HINSTANCE hInst);
BOOL ProcessAttach(HMODULE hDll);
BOOL ProcessDetach(HMODULE hDll);

BOOL(__stdcall * Real_CreateProcessA)(LPCSTR a0,
	LPSTR a1,
	LPSECURITY_ATTRIBUTES a2,
	LPSECURITY_ATTRIBUTES a3,
	BOOL a4,
	DWORD a5,
	LPVOID a6,
	LPCSTR a7,
	LPSTARTUPINFOA a8,
	LPPROCESS_INFORMATION a9)
	= CreateProcessA;

BOOL(__stdcall * Real_CreateProcessW)(LPCWSTR a0,
	LPWSTR a1,
	LPSECURITY_ATTRIBUTES a2,
	LPSECURITY_ATTRIBUTES a3,
	BOOL a4,
	DWORD a5,
	LPVOID a6,
	LPCWSTR a7,
	LPSTARTUPINFOW a8,
	LPPROCESS_INFORMATION a9)
	= CreateProcessW;

#if (PSAPI_VERSION > 1)
#define Real_EnumProcessModules Real_K32EnumProcessModules
#define Mine_EnumProcessModules Mine_K32EnumProcessModules
#else
#endif

BOOL(__stdcall * Real_EnumProcessModules)(
	HANDLE hProcess,
	HMODULE *lphModule,
	DWORD cb,
	LPDWORD lpcbNeeded)
	= EnumProcessModules;

BOOL(__stdcall* Real_WaitForDebugEvent)(
	_Out_ LPDEBUG_EVENT lpDebugEvent,
	_In_ DWORD dwMilliseconds
	) = WaitForDebugEvent;

BOOL(__stdcall* Real_TerminateProcess)(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode)
	= TerminateProcess;

BOOL(__stdcall* Real_IsDebuggerPresent)()
	= IsDebuggerPresent;

BOOL(__stdcall* Real_IsHungAppWindow)(_In_ HWND hwnd)
	= IsHungAppWindow;

LPVOID(__stdcall* Real_MapViewOfFile)(
	_In_ HANDLE hFileMappingObject,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwFileOffsetHigh,
	_In_ DWORD dwFileOffsetLow,
	_In_ SIZE_T dwNumberOfBytesToMap)
	= MapViewOfFile;

DWORD(__stdcall* Real_timeGetTime)()
	= timeGetTime;

BOOL(__stdcall* Real_IsWindow)(_In_opt_ HWND hWnd)
	= IsWindow;

BOOL(__stdcall* Real_PostMessageA)(
	_In_opt_ HWND hWnd,
	_In_ UINT Msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
	= PostMessageA;

HANDLE(__stdcall* Real_CreateFileMappingA)(
	_In_ HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_ DWORD flProtect,
	_In_ DWORD dwMaximumSizeHigh,
	_In_ DWORD dwMaximumSizeLow,
	_In_opt_ LPCSTR lpName)
	= CreateFileMappingA;

HWND(__stdcall* Real_CreateWindowExA)(
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
	= CreateWindowExA;

DWORD (__stdcall* Real_WaitForMultipleObjectsEx)(
	_In_ DWORD nCount,
	_In_reads_(nCount) CONST HANDLE * lpHandles,
	_In_ BOOL bWaitAll,
	_In_ DWORD dwMilliseconds,
	_In_ BOOL bAlertable)
= WaitForMultipleObjectsEx;
