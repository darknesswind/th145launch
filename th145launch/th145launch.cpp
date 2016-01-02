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
#include <thread>

const int buffSize = 0x100;

void ProcessWinXP(char *pTargetName)
{
	OSVERSIONINFOA info = { sizeof(OSVERSIONINFOA) };
	GetVersionExA(&info);
	if (info.dwMajorVersion == 5)  // winXP
	{
		char xpName[buffSize] = { 0 };
		memcpy(xpName, pTargetName, buffSize);
		int len = strlen(xpName);
		int insertPos = len - 1;
		for (; insertPos >= 0; --insertPos)
		{
			if (xpName[insertPos] == '.')
				break;
		}
		if (insertPos < 0)
			insertPos = len;
		memcpy(xpName + insertPos, "_xp.exe\0", 8);

		std::cout << "detected win xp..." << std::endl;
		CopyFileA(pTargetName, xpName, FALSE);

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
			err = fopen_s(&hFile, xpName, "r+b");
			if (0 == err)
			{
				fseek(hFile, 0, SEEK_SET);
				fwrite(&buf, sizeof(buf), 1, hFile);
				fclose(hFile);
				memcpy(pTargetName, xpName, buffSize);
			}
			else
				std::cout << "open " << xpName << " failed!" << std::endl;
		}
		else
		{
			std::cout << "open " << pTargetName << " failed!" << std::endl;
		}
	}
}

int main()
{
#ifdef _DEBUG
// 	SetCurrentDirectoryW(LR"(D:\Game\Touhou\上海アリス幻樂団\[TH145]东方深秘录\)");
	SetCurrentDirectoryW(LR"(D:\Game\Touhou\黄昏边境\収集荷取 金\)");
#endif
	char targetName[buffSize] = { 0 };
	::GetPrivateProfileStringA("default", "appName", "th145.exe", targetName, buffSize, ".\\thlaunch.ini");
	if (0 == targetName[0])
		targetName[0] = 'x';
	ProcessWinXP(targetName);

	HANDLE hReadPipe = nullptr;
	HANDLE hWritePipe = nullptr;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
	{
		std::cout << "create pipe failed!" << std::endl;
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
	startupinfo.dwFlags = STARTF_USESTDHANDLES;
// 	startupinfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	startupinfo.hStdOutput = hWritePipe;
	char path[256];
	strcpy_s(path, targetName);
	BOOL res = DetourCreateProcessWithDllExA(
		nullptr,
		path,
		nullptr,
		nullptr,
		TRUE,
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

		std::thread worker([&]()
		{
			char buff[1024] = { 0 };
			while (true)
			{
				DWORD dwReaded = 0;
				if (!ReadFile(hReadPipe, buff, sizeof(buff), &dwReaded, NULL))
					break;
				std::cout << buff;

				if (buff[0] == '#')
					break;
			}
		});
		worker.detach();

		WaitForSingleObject(procInfo.hProcess, INFINITE);
		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);

		std::cout << "process exited." << std::endl;
	}
	else
	{
		std::cout << "create process failed!" << std::endl;
		system("pause");
	}

	if (hWritePipe)
		CloseHandle(hWritePipe);
	if (hReadPipe)
		CloseHandle(hReadPipe);

	hWritePipe = nullptr;
	hReadPipe = nullptr;
#ifdef _DEBUG
	system("pause");
#endif
    return 0;
}
