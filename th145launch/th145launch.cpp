// th145launch.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#if _MSC_VER >= 1300
#include <winsock2.h>
#endif
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <detours.h>
#include <cassert>
#include <iostream>

int main()
{
#ifdef _DEBUG
	SetCurrentDirectoryW(LR"(C:\Game\東方\th145\)");
#endif
	LPCSTR pTargetName = R"(th145.exe)";
	OSVERSIONINFOA info = { sizeof(OSVERSIONINFOA) };
	GetVersionExA(&info);
	if (info.dwMajorVersion == 5)  // winXP
	{
		std::cout << "detected win xp..." << std::endl;
		CopyFileA("th145.exe", "th145_xp.exe", TRUE);

		FILE* hFile = nullptr;
		errno_t err = fopen_s(&hFile, pTargetName, "rb");
		if (0 == err)
		{
			char buf[0x200] = { 0 };
			fseek(hFile, 0, SEEK_SET);
			fread_s(&buf, sizeof(buf), sizeof(buf), 1, hFile);
			fclose(hFile);

			buf[0x180] = 5;
			buf[0x188] = 5;
			err = fopen_s(&hFile, "th145_xp.exe", "r+b");
			if (0 == err)
			{
				fseek(hFile, 0, SEEK_SET);
				fwrite(&buf, sizeof(buf), 1, hFile);
				fclose(hFile);
				pTargetName = R"(th145_xp.exe)";
			}
			else
				std::cout << "open th145_xp.exe failed!" << std::endl;
		}
		else
		{
			std::cout << "open th145.exe failed!" << std::endl;
		}
	}

	char szDllPath[300];
	char sDirver[MAX_PATH];
	char sPath[MAX_PATH];
	char sName[MAX_PATH];
	char sExt[MAX_PATH];
	GetModuleFileNameA(GetModuleHandleA(NULL), szDllPath, ARRAYSIZE(szDllPath));
	_splitpath_s(szDllPath, sDirver, sPath, sName, sExt);
	sprintf_s(szDllPath, "%s%s\\th145hook.dll", sDirver, sPath);

	PROCESS_INFORMATION procInfo = { 0 };
	STARTUPINFOA startupinfo = { 0 };
	startupinfo.cb = sizeof(STARTUPINFOA);
	char path[256];
	strcpy_s(path, pTargetName);
	BOOL res = DetourCreateProcessWithDllExA(
		nullptr,
		path,
		nullptr,
		nullptr,
		FALSE,
		CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED,
		nullptr,
		nullptr,
		&startupinfo,
		&procInfo,
		szDllPath,
		CreateProcessA);

	assert(res);
	if (res)
	{
		std::cout << "create process succeed!" << std::endl;
		ResumeThread(procInfo.hThread);
		std::cout << "waiting process exit..." << std::endl;
		WaitForSingleObject(procInfo.hProcess, INFINITE);
		std::cout << "process exited." << std::endl;
	}
	else
	{
		std::cout << "create process failed!" << std::endl;
	}
	system("pause");
    return 0;
}
