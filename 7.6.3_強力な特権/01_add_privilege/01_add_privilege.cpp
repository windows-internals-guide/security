#include <windows.h>
#include <ntsecapi.h>
#include <strsafe.h>

BOOL AddPrivilege(LPCWSTR lpszPrivilege, PSID pSid, BOOL bAdd);

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("特権有効のため管理者として実行してください。");
		return -1;
	}

	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID  pSid = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pSid, &dwSidSize);

	LPCWSTR lpszPrivilege[] = {
		SE_ASSIGNPRIMARYTOKEN_NAME
		SE_TCB_NAME,
		SE_RELABEL_NAME,
		SE_AUDIT_NAME
	};
	int i;
	int nPrivilegeCount = sizeof(lpszPrivilege) / sizeof(lpszPrivilege[0]);
	int nExitCode = 0;

	for (i = 0; i < nPrivilegeCount; i++) {
		if (!AddPrivilege(lpszPrivilege[i], pSid, TRUE)) {
			printf("%wsの追加に失敗しました。", lpszPrivilege[i]);
			nExitCode = -1;
			break;
		}
	}

	if (nExitCode == 0)
		printf("全ての特権を追加した。");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	LocalFree(pSid);

	return nExitCode;
}

BOOL AddPrivilege(LPCWSTR lpszPrivilege, PSID pSid, BOOL bAdd)
{
	NTSTATUS              ns;
	LSA_HANDLE            hPolicy;
	LSA_UNICODE_STRING    lsaString;
	LSA_OBJECT_ATTRIBUTES objectAttributes;
	BOOL                  bResult = FALSE;

	ZeroMemory(&objectAttributes, sizeof(LSA_OBJECT_ATTRIBUTES));
	objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	ns = LsaOpenPolicy(NULL, &objectAttributes, POLICY_LOOKUP_NAMES, &hPolicy);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS)
		return FALSE;

	lsaString.Buffer = (LPWSTR)lpszPrivilege;
	lsaString.Length = (USHORT)(lstrlenW(lsaString.Buffer) * sizeof(WCHAR));
	lsaString.MaximumLength = lsaString.Length + sizeof(WCHAR);

	if (bAdd) {
		ns = LsaAddAccountRights(hPolicy, pSid, &lsaString, 1);
		if (LsaNtStatusToWinError(ns) == ERROR_SUCCESS)
			bResult = TRUE;
	}
	else {
		ns = LsaRemoveAccountRights(hPolicy, pSid, FALSE, &lsaString, 1);
		if (LsaNtStatusToWinError(ns) == ERROR_SUCCESS)
			bResult = TRUE;
	}

	LsaClose(hPolicy);

	return bResult;
}