#include <stdio.h>
#include <windows.h>
#include <ntsecapi.h>
#include <winsafer.h>

#define FLAG_IL 0x01
#define FLAG_ADMIN 0x02
#define FLAG_PRIV 0x04
#define FLAG_ALL 0x7

int CheckTokenInfo(HANDLE hToken, LPCWSTR lpszName);
DWORD CheckIntegrityLevel(HANDLE hToken);
DWORD CheckAdministrators(HANDLE hToken);
int CheckPrivileges(HANDLE hToken);
HANDLE GetFilterdAdminToken(HANDLE hTokenFull);
HANDLE GetLuaToken(HANDLE hTokenFull);
HANDLE GetSaferNormalUserToken(HANDLE hTokenFull);

// フィルターされた管理者トークンの情報を確認

int main()
{
	HANDLE hTokenFull;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return -1;
	}

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTokenFull);

	HANDLE hTokenFilterdAmin = GetFilterdAdminToken(hTokenFull);
	HANDLE hTokenSafer = GetSaferNormalUserToken(hTokenFull);
	HANDLE hTokenLua = GetLuaToken(hTokenFull);

	DWORD dwFilterdAmin = CheckTokenInfo(hTokenFilterdAmin, L"FilterdAmin");
	DWORD dwSafer = CheckTokenInfo(hTokenSafer, L"Safer");
	DWORD dwLua = CheckTokenInfo(hTokenLua, L"Lua");

	CloseHandle(hTokenFull);
	CloseHandle(hTokenFilterdAmin);
	CloseHandle(hTokenSafer);
	CloseHandle(hTokenLua);

	int nExitCode = -1;
	if (dwFilterdAmin == FLAG_ALL && dwSafer == (FLAG_ADMIN | FLAG_PRIV) && dwLua == (FLAG_ADMIN | FLAG_PRIV)) {
		printf("トークン情報は正しい");
		nExitCode = 0;
	}
	else
		printf("トークン情報は正しくない");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

int CheckTokenInfo(HANDLE hToken, LPCWSTR lpszName)
{
	DWORD dwFlags = 0;

	dwFlags |= CheckIntegrityLevel(hToken);
	dwFlags |= CheckAdministrators(hToken);
	dwFlags |= CheckPrivileges(hToken);

	return dwFlags;
}

DWORD CheckIntegrityLevel(HANDLE hToken)
{
	DWORD                  dwLength;
	PTOKEN_MANDATORY_LABEL pMandatoryLabel;

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
	pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, dwLength, &dwLength);

	DWORD dwSubAuthorityCount = *GetSidSubAuthorityCount(pMandatoryLabel->Label.Sid);
	DWORD dwRid = *GetSidSubAuthority(pMandatoryLabel->Label.Sid, dwSubAuthorityCount - 1);

	LocalFree(pMandatoryLabel);

	return dwRid == SECURITY_MANDATORY_MEDIUM_RID ? FLAG_IL : 0;
}

DWORD CheckAdministrators(HANDLE hToken)
{
	DWORD         i;
	DWORD         dwLength;
	DWORD         dwReturnFlag = 0;
	PTOKEN_GROUPS pTokenGroups;
	PSID          pSidAdministrators;

	dwLength = SECURITY_MAX_SID_SIZE;
	pSidAdministrators = (PSID)LocalAlloc(LPTR, dwLength);
	CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pSidAdministrators, &dwLength);

	GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength);

	for (i = 0; i < pTokenGroups->GroupCount; i++) {
		if (EqualSid(pSidAdministrators, pTokenGroups->Groups[i].Sid)) {
			if (pTokenGroups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) {
				dwReturnFlag = FLAG_ADMIN;
				break;
			}
		}
	}

	LocalFree(pTokenGroups);
	LocalFree(pSidAdministrators);

	return dwReturnFlag;
}

int CheckPrivileges(HANDLE hToken)
{
	DWORD             i, j;
	DWORD             dwLength;
	PTOKEN_PRIVILEGES pTokenPrivileges;
	WCHAR             szProgramName[256];
	LPCWSTR           lpszPrivileges[] = {
		SE_CHANGE_NOTIFY_NAME, SE_SHUTDOWN_NAME, SE_UNDOCK_NAME,
		SE_INC_WORKING_SET_NAME, SE_TIME_ZONE_NAME
	};
	DWORD             dwTargetPrivilegeCount = sizeof(lpszPrivileges) / sizeof(lpszPrivileges[0]);
	DWORD             dwReturnFlag = 0;

	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength);

	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
		dwLength = sizeof(szProgramName) / sizeof(WCHAR);
		LookupPrivilegeName(NULL, &pTokenPrivileges->Privileges[i].Luid, szProgramName, &dwLength);
		for (j = 0; j < dwTargetPrivilegeCount; j++) {
			if (lstrcmp(szProgramName, lpszPrivileges[j]) == 0)
				break;
		}

		if (j != dwTargetPrivilegeCount) {
			dwReturnFlag = FLAG_PRIV;
			break;
		}
	}

	LocalFree(pTokenPrivileges);

	return dwReturnFlag;
}

#if 1
HANDLE GetFilterdAdminToken(HANDLE hTokenFull)
{
	HANDLE               hTokenNormal;
	TOKEN_LINKED_TOKEN   linkedToken;
	TOKEN_ELEVATION_TYPE tokenElevationType;
	DWORD                dwLength;

	GetTokenInformation(hTokenFull, TokenElevationType, &tokenElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwLength);
	if (tokenElevationType == TokenElevationTypeFull) {
		GetTokenInformation(hTokenFull, TokenLinkedToken, &linkedToken, sizeof(TOKEN_LINKED_TOKEN), &dwLength);
		hTokenNormal = linkedToken.LinkedToken;
	}
	else
		hTokenNormal = NULL;

	return hTokenNormal;
}
#else
HANDLE GetFilterdAdminToken(HANDLE hTokenFull)
{
	DWORD   dwProcessId;
	HANDLE  hProcess;
	HANDLE  hTokenNormal, hTokenDuplicate;

	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
	if (hProcess == NULL)
		return NULL;

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hTokenNormal)) {
		CloseHandle(hProcess);
		return NULL;
	}

	DuplicateTokenEx(hTokenNormal, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &hTokenDuplicate);

	CloseHandle(hProcess);
	CloseHandle(hTokenNormal);

	return hTokenDuplicate;
}
#endif

HANDLE GetSaferNormalUserToken(HANDLE hTokenFull)
{
	HANDLE             hTokenNormal;
	SAFER_LEVEL_HANDLE hLevel;

	SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, 0, &hLevel, NULL);
	SaferComputeTokenFromLevel(hLevel, hTokenFull, &hTokenNormal, 0, NULL);
	SaferCloseLevel(hLevel);

	return hTokenNormal;
}

HANDLE GetLuaToken(HANDLE hTokenFull)
{
	HANDLE hTokenRestricted;

	CreateRestrictedToken(hTokenFull, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &hTokenRestricted);

	return hTokenRestricted;
}
