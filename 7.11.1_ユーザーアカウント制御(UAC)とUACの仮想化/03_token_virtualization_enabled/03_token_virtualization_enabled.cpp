#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

BOOL IsVirtualization(HANDLE hProcess);
DWORD GetProcessIdFromFileName(LPCWSTR lpszFileName);

// エクスプローラーが仮想化されていないことを確認

int main()
{
	HANDLE hProcess;
	DWORD  dwProcessId = GetProcessIdFromFileName(L"explorer.exe");

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	if (hProcess == NULL) {
		printf("プロセスのハンドルを取得できない");
		return -1;
	}

	int nExitCode = -1;
	if (!IsVirtualization(hProcess)) {
		printf("explorer.exeは仮想化されていない");
		nExitCode = 0;
	}
	else
		printf("explorer.exeは仮想化されている");

	CloseHandle(hProcess);

	return nExitCode;
}

BOOL IsVirtualization(HANDLE hProcess)
{
	HANDLE hToken;
	DWORD  dwEnabled;
	DWORD  dwLength = sizeof(DWORD);

	OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenVirtualizationEnabled, &dwEnabled, sizeof(dwEnabled), &dwLength);
	CloseHandle(hToken);

	return dwEnabled == 1;
}

DWORD GetProcessIdFromFileName(LPCWSTR lpszFileName)
{
	HANDLE         hSnapshot;
	DWORD          dwProcessId;
	PROCESSENTRY32 pe;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	dwProcessId = -1;
	do {
		if (lstrcmp(pe.szExeFile, lpszFileName) == 0) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return dwProcessId;
}