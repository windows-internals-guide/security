#include <windows.h>
#include <authz.h>
#include <strsafe.h>

#pragma comment (lib, "authz.lib")

BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください");
		return -1;
	}
	
	AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager;

	if (AuthzInitializeResourceManager(0, NULL, NULL, NULL, L"", &hAuthzResourceManager)) {
		printf("SE_AUDIT_NAMEの有効化の前に関数が成功してしまった。");
		AuthzFreeResourceManager(hAuthzResourceManager);
		return -1;
	}
	
	if (!EnablePrivilege(SE_AUDIT_NAME, TRUE)) {
		return -1;
	}

	int nExitCode = -1;

	if (AuthzInitializeResourceManager(0, NULL, NULL, NULL, L"", &hAuthzResourceManager)) {
		printf("AuthzInitializeResourceManagerの呼び出しに成功した。");
		AuthzFreeResourceManager(hAuthzResourceManager);
		nExitCode = 0;
	}
	else
		printf("AuthzInitializeResourceManagerの呼び出しに失敗した。");

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