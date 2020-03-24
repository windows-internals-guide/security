#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <strsafe.h>

BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);
DWORD GetProcessIdFromFileName(LPCWSTR lpszFileName);

// SE_DEBUG_NAMEの有効化でシステムプロセスをフルアクセスでオープンできることを確認

int main()
{
	HANDLE hProcess;
	DWORD  dwProcessId;
	DWORD  dwAccessMask = PROCESS_ALL_ACCESS;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("特権有効のため管理者として実行してください。");
		return -1;
	}

	dwProcessId = GetProcessIdFromFileName(L"lsass.exe");

	hProcess = OpenProcess(dwAccessMask, FALSE, dwProcessId);
	if (hProcess != NULL) {
		printf("特権を有効にしていないのにシステムプロセスをオープンできた。");
		CloseHandle(hProcess);
		return -1;
	}

	if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
		return -1;
	}

	int nExitCode = -1;

	hProcess = OpenProcess(dwAccessMask, FALSE, dwProcessId);
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

BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled)
{
	BOOL             bResult;
	LUID             luid;
	HANDLE           hToken;
	TOKEN_PRIVILEGES tokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
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