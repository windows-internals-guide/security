#include <windows.h>
#include <strsafe.h>

BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

// SE_TAKE_OWNERSHIP_NAMEの有効化でWRITE_OWNERによるオープンが成功することを確認

int main()
{
	HANDLE hFile;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("特権有効のため管理者として実行してください。");
		return -1;
	}
	
	WCHAR szFilePath[256];
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\atl.dll", szFilePath, sizeof(szFilePath) / sizeof(szFilePath[0]));

	hFile = CreateFile(szFilePath, WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		printf("特権を有効にしていないのにWRITE_OWNER権を取得できた。");
		return -1;
	}

	if (!EnablePrivilege(SE_TAKE_OWNERSHIP_NAME, TRUE)) {
		return -1;
	}

	int nExitCode = -1;

	hFile = CreateFile(szFilePath, WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		printf("TrustedInstallerファイルのWRITE_OWNER権を取得しました。");
		CloseHandle(hFile);
		nExitCode = 0;
	}
	else
		printf("WRITE_OWNER権の取得に失敗しました。");

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