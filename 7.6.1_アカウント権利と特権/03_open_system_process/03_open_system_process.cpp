#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

HANDLE OpenSystemProcess();
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

// SE_DEBUG_NAME特権が有効な場合に、システムプロセスをオープンできることを確認

int main()
{
	HANDLE hProcess;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return -1;
	}

	hProcess = OpenSystemProcess();
	if (hProcess != NULL) {
		CloseHandle(hProcess);
		return -1;
	}

	EnablePrivilege(SE_DEBUG_NAME, TRUE);

	int nExitCode = -1;
	hProcess = OpenSystemProcess();
	if (hProcess != NULL) {
		printf("システムプロセスをオープンした。");
		CloseHandle(hProcess);
		nExitCode = 0;
	}
	else
		printf("システムプロセスをオープンできなかった。");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

HANDLE OpenSystemProcess()
{
	HANDLE         hSnapshot;
	DWORD          dwProcessId;
	PROCESSENTRY32 pe;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	dwProcessId = 0;
	do {
		if (lstrcmp(pe.szExeFile, L"lsass.exe") == 0) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
}

BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled)
{
	BOOL             bResult;
	LUID             luid;
	HANDLE           hToken;
	TOKEN_PRIVILEGES tokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = bEnabled ? SE_PRIVILEGE_ENABLED : 0;

	bResult = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	CloseHandle(hToken);

	return bResult && GetLastError() == ERROR_SUCCESS;
}