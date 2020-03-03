#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL CheckTokenPrivileges(HANDLE hToken, LPCWSTR lpszPrivilege);
BOOL CheckPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege);
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

// 特権を有効化しておかないと、PrivilegeCheck関数は失敗することを確認

int main()
{
	HANDLE hToken;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return 0;
	}

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	BOOL bResult1 = CheckTokenPrivileges(hToken, SE_DEBUG_NAME);
	BOOL bResult2 = CheckPrivilege(hToken, SE_DEBUG_NAME);

	int nExitCode = -1;
	if (bResult1 && !bResult2) {
		EnablePrivilege(SE_DEBUG_NAME, TRUE);
		if (CheckPrivilege(hToken, SE_DEBUG_NAME)) {
			printf("SE_DEBUG_NAME特権は割り当てられている。");
			nExitCode = 0;
		}
		else
			printf("SE_DEBUG_NAME特権の有効化に失敗。");
	}
	else
		printf("SE_DEBUG_NAME特権は割り当てられていない。");
		
#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL CheckTokenPrivileges(HANDLE hToken, LPCWSTR lpszPrivilege)
{
	DWORD             i, dwLength;
	PTOKEN_PRIVILEGES pTokenPrivileges;
	LUID              luid;
	PLUID             pluid;
	BOOL              bResult = FALSE;

	LookupPrivilegeValue(NULL, lpszPrivilege, &luid);

	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength);

	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
		pluid = &pTokenPrivileges->Privileges[i].Luid;
		if (pluid->LowPart == luid.LowPart && pluid->HighPart == luid.HighPart) {
			bResult = TRUE;
			break;
		}
	}

	LocalFree(pTokenPrivileges);

	return bResult;
}

BOOL CheckPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege)
{
	LUID          luid;
	PRIVILEGE_SET privilege;

	LookupPrivilegeValue(NULL, lpszPrivilege, &luid);

	privilege.PrivilegeCount = 1;
	privilege.Privilege[0].Luid = luid;
	privilege.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bResult;

	PrivilegeCheck(hToken, &privilege, &bResult);

	return bResult;
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