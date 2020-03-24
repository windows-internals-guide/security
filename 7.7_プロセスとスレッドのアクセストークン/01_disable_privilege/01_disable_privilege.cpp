#include <windows.h>
#include <stdio.h>

BOOL IsShutdown(HANDLE hToken);
BOOL EnablePrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnabled);

// 特権削除の効果を確認

int main()
{
	HANDLE hThread;
	HANDLE hToken, hTokenRestricted;

	ImpersonateSelf(SecurityImpersonation);
	hThread = GetCurrentThread();
	OpenThreadToken(hThread, TOKEN_ALL_ACCESS, TRUE, &hToken);
	CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hTokenRestricted);
	SetThreadToken(&hThread, hTokenRestricted);

	int nExitCode = -1;
	if (!IsShutdown(hTokenRestricted)) {
		printf("特権を削除したため、シャットダウン特権を有効化できない");
		nExitCode = 0;
	}
	else
		printf("シャットダウン特権を有効にできてしまった");

	RevertToSelf();

	CloseHandle(hTokenRestricted);
	CloseHandle(hToken);

	return nExitCode;
}

BOOL IsShutdown(HANDLE hToken)
{
	return EnablePrivilege(hToken, SE_SHUTDOWN_NAME, TRUE);
}

BOOL EnablePrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnabled)
{
	BOOL             bResult;
	LUID             luid;
	TOKEN_PRIVILEGES tokenPrivileges;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = bEnabled ? SE_PRIVILEGE_ENABLED : 0;

	bResult = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	return bResult && GetLastError() == ERROR_SUCCESS;
}