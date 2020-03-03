#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>

BOOL IsInteractiveLogon();
BOOL CheckAccountRights(PSID pSid, LPCWSTR lpszAccountRights, LPCWSTR lpszDenyAccountRights);

// Administratorsグループに対話型ログオンが許可されているか確認

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("LsaOpenPolicyのため管理者として実行してください。");
		return -1;
	}

	int nExitCode = -1;
	if (IsInteractiveLogon()) {
		printf("Administratorsグループは対話型ログオンが許可される");
		nExitCode = 0;
	}
	else
		printf("Administratorsグループは対話型ログオンが許可されない");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL IsInteractiveLogon()
{
	BOOL  bResult;
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID  pSid = (PSID)LocalAlloc(LPTR, dwSidSize);

	CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pSid, &dwSidSize);

	bResult = CheckAccountRights(pSid, SE_INTERACTIVE_LOGON_NAME, SE_DENY_INTERACTIVE_LOGON_NAME);

	LocalFree(pSid);

	return bResult;
}

BOOL CheckAccountRights(PSID pSid, LPCWSTR lpszAccountRights, LPCWSTR lpszDenyAccountRights)
{
	ULONG                 i;
	ULONG                 uCount;
	NTSTATUS              ns;
	LSA_HANDLE            hPolicy;
	LSA_OBJECT_ATTRIBUTES objectAttributes;
	PLSA_UNICODE_STRING   plsaString;
	BOOL                  bResult1 = FALSE;
	BOOL                  bResult2 = TRUE;

	ZeroMemory(&objectAttributes, sizeof(LSA_OBJECT_ATTRIBUTES));
	objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	ns = LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &hPolicy);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		return FALSE;
	}

	ns = LsaEnumerateAccountRights(hPolicy, pSid, &plsaString, &uCount);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		return FALSE;
	}

	for (i = 0; i < uCount; i++) {
		if (lstrcmp(plsaString[i].Buffer, lpszAccountRights) == 0) {
			bResult1 = TRUE;
		}
		else if (lstrcmp(plsaString[i].Buffer, lpszDenyAccountRights) == 0) {
			bResult2 = FALSE;
		}
	}

	LsaFreeMemory(plsaString);

	return bResult1 && bResult2;
}