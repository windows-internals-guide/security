#include <stdio.h>
#include <windows.h>
#include <aclapi.h>
#include <tlhelp32.h>

BOOL Check_OpenFile();
BOOL Check_OpenProcess();
void SetLowToken();
DWORD GetProcessIdFromFileName(LPCWSTR lpszFileName);

// 整合性レベル「低」のプロセスはオブジェクトに何ができるか確認

int main()
{
	if (!Check_OpenFile() || !Check_OpenProcess()) {
		printf("整合性レベル「中」だが、ファイルかプロセスを開けない");
		return -1;
	}
	
	SetLowToken();
	
	int nExitCode = -1;
	
	if (Check_OpenFile()) {
		if (!Check_OpenProcess()) {
			printf("プロセスは開けないので正解");
			nExitCode = 0;
		}
		else {
			printf("整合性レベル「低」のプロセスが「中」のプロセスをオープンできてしまった");
		}
	}
	
	return nExitCode;
}

BOOL Check_OpenFile()
{
	HANDLE hFile;
	WCHAR  szModuleName[MAX_PATH];

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	hFile = CreateFile(szModuleName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	
	CloseHandle(hFile);
	
	return TRUE;
}

BOOL Check_OpenProcess()
{
	HANDLE hProcess;
	DWORD dwProcessId = GetProcessIdFromFileName(L"explorer.exe");

	hProcess = OpenProcess(PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProcess == NULL) {
		return FALSE;
	}
	
	CloseHandle(hProcess);
	
	return TRUE;
}

void SetLowToken()
{
	HANDLE                hToken;
	DWORD                 dwSidSize;
	TOKEN_MANDATORY_LABEL mandatoryLabel;
	PSID                  pSidLow;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hToken)) {
		return;
	}

	dwSidSize = SECURITY_MAX_SID_SIZE;
	pSidLow = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinLowLabelSid, NULL, pSidLow, &dwSidSize);

	mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
	mandatoryLabel.Label.Sid = pSidLow;
	SetTokenInformation(hToken, TokenIntegrityLevel, &mandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pSidLow));

	LocalFree(pSidLow);
	CloseHandle(hToken);
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
