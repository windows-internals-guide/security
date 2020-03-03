#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL GetLsaProcessId(LPVOID lpData, DWORD dwSize);
DWORD OpenSystemThreadId(DWORD dwOwnerProcessId);

// アクセスチェックはハンドルの取得時だけでなく、使用時にも発生している

int main()
{
	DWORD dwThreadId;
	DWORD dwProcessId;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("プロセス作成のため管理者として実行してください。");
		return -1;
	}

	GetLsaProcessId(&dwProcessId, sizeof(DWORD));
	dwThreadId = OpenSystemThreadId(dwProcessId);

	HANDLE hThread = OpenThread(SYNCHRONIZE, FALSE, dwThreadId); // THREAD_QUERY_INFORMATION
	if (hThread == NULL) {
		printf("ハンドルの取得に失敗しました。");
		return -1;
	}
	
	int nExitCode = -1;
	GetThreadPriority(hThread);
	if (GetLastError() == ERROR_ACCESS_DENIED) {
		printf("関数の呼び出しに失敗した。");
		nExitCode = 0;
	}
	else
		printf("関数の呼び出しに成功してしまった。");

	CloseHandle(hThread);

	return nExitCode;
}

DWORD OpenSystemThreadId(DWORD dwOwnerProcessId)
{
	HANDLE        hSnapshot;
	DWORD         dwThreadId;
	THREADENTRY32 te;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	te.dwSize = sizeof(THREADENTRY32);
	Thread32First(hSnapshot, &te);

	dwThreadId = 0;
	do {
		if (te.th32OwnerProcessID == dwOwnerProcessId) {
			dwThreadId = te.th32ThreadID;
			break;
		}
	} while (Thread32Next(hSnapshot, &te));

	CloseHandle(hSnapshot);

	return dwThreadId;
}

BOOL GetLsaProcessId(LPVOID lpData, DWORD dwSize)
{
	HKEY hKey;
	LONG lResult;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_QUERY_VALUE, &hKey);
	if (lResult == ERROR_SUCCESS) {
		lResult = RegQueryValueEx(hKey, L"LsaPid", NULL, NULL, (LPBYTE)lpData, &dwSize);
		RegCloseKey(hKey);
		return TRUE;
	}
	else
		return FALSE;
}
