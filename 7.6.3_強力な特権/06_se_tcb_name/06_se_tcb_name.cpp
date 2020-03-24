#include <windows.h>
#include <ntsecapi.h>
#include <strsafe.h>

#pragma comment (lib, "secur32.lib")

BOOL EstablisheLSAServer(PSID pSidGroup, HANDLE* phToken);
BOOL MyLogonUser(HANDLE hLsa, ULONG uPackageId, LPWSTR lpszUserName, LPWSTR lpszPassword, LPWSTR lpszDomainName, PSID pSidGroup, HANDLE* hToken);
ULONG InitString(PLSA_STRING plsaString, LPCSTR lpszString);
ULONG InitUnicodeString(PLSA_UNICODE_STRING plsaString, LPWSTR lpszString);
void FormatBuffer(LPBYTE* lp, PUNICODE_STRING pString);
PSID GetGroupSid();
BOOL IsSidEnabled(HANDLE hToken, PSID pSidGroup);
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

int main()
{
	HANDLE hToken;
	PSID   pSidGroup;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("特権有効のため管理者として実行してください。");
		return -1;
	}

	if (!EnablePrivilege(SE_TCB_NAME, TRUE)) {
		printf("SE_TCB_NAME特権の有効に失敗。");
		return -1;
	}

	pSidGroup = GetGroupSid();

	int nExitCode = -1;

	if (EstablisheLSAServer(pSidGroup, &hToken)) {
		if (IsSidEnabled(hToken, pSidGroup)) {
			printf("ログオンSIDがトークングループに含まれた。");
			nExitCode = 0;
		}
		else
			printf("ログオンSIDがトークングループに含まれていない。");
		CloseHandle(hToken);
	}
	else
		printf("ログオンに失敗。");

	LocalFree(pSidGroup);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL EstablisheLSAServer(PSID pSidGroup, HANDLE* phToken)
{
	HANDLE               hLsa;
	ULONG                uPackageId;
	NTSTATUS             ns;
	LSA_STRING           lsaString;
	LSA_OPERATIONAL_MODE mode;
	BOOL                 bResult;
	WCHAR                szUserName[] = L"";
	WCHAR                szPassword[] = L"";
	
	if (szUserName[0] == '\0' || szPassword[0] == '\0') {
		printf("ユーザー名またはパスワードが設定されていない");
		return FALSE;
	}

	InitString(&lsaString, "MyLogonProcess");
	ns = LsaRegisterLogonProcess(&lsaString, &hLsa, &mode);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		printf("LSAサーバーへの接続に失敗。");
		return FALSE;
	}

	InitString(&lsaString, MSV1_0_PACKAGE_NAME);
	ns = LsaLookupAuthenticationPackage(hLsa, &lsaString, &uPackageId);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		printf("認証パッケージのIDの取得に失敗。");
		LsaDeregisterLogonProcess(hLsa);
		return FALSE;
	}

	bResult = MyLogonUser(hLsa, uPackageId, szUserName, szPassword, NULL, pSidGroup, phToken);

	LsaDeregisterLogonProcess(hLsa);

	return bResult;
}

BOOL MyLogonUser(HANDLE hLsa, ULONG uPackageId, LPWSTR lpszUserName, LPWSTR lpszPassword, LPWSTR lpszDomainName, PSID pSidGroup, HANDLE* phToken)
{
	LUID                        luid;
	ULONG                       uBufferLength;
	ULONG                       uProfileLength;
	LPBYTE                      lp;
	NTSTATUS                    ns;
	NTSTATUS                    nsSub;
	LSA_STRING                  lsaOriginal;
	QUOTA_LIMITS                limits;
	TOKEN_SOURCE                tokenSource;
	MSV1_0_INTERACTIVE_LOGON    msvLogon;
	PMSV1_0_INTERACTIVE_LOGON   pmsvLogon;
	PMSV1_0_INTERACTIVE_PROFILE pmsvProfile;
	TOKEN_GROUPS                tokenGroups;

	InitString(&lsaOriginal, "origial");

	uBufferLength = sizeof(MSV1_0_INTERACTIVE_LOGON);
	uBufferLength += InitUnicodeString(&msvLogon.UserName, lpszUserName);
	uBufferLength += InitUnicodeString(&msvLogon.Password, lpszPassword);
	uBufferLength += InitUnicodeString(&msvLogon.LogonDomainName, lpszDomainName);
	msvLogon.MessageType = MsV1_0InteractiveLogon;

	lp = (LPBYTE)LocalAlloc(LPTR, uBufferLength);
	if (lp == NULL)
		return FALSE;
	CopyMemory(lp, (PVOID)& msvLogon, sizeof(MSV1_0_INTERACTIVE_LOGON));
	pmsvLogon = (PMSV1_0_INTERACTIVE_LOGON)lp;

	lp += sizeof(MSV1_0_INTERACTIVE_LOGON);
	FormatBuffer(&lp, &pmsvLogon->UserName);

	lp += pmsvLogon->UserName.Length;
	FormatBuffer(&lp, &pmsvLogon->Password);

	lp += pmsvLogon->Password.Length;
	FormatBuffer(&lp, &pmsvLogon->LogonDomainName);

	StringCchCopyA(tokenSource.SourceName, TOKEN_SOURCE_LENGTH, "Unknown");
	AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

	tokenGroups.GroupCount = 1;
	tokenGroups.Groups[0].Sid = pSidGroup;
	tokenGroups.Groups[0].Attributes = SE_GROUP_ENABLED;

	ns = LsaLogonUser(hLsa, &lsaOriginal, Interactive, uPackageId,
		(PVOID)pmsvLogon, uBufferLength, &tokenGroups, &tokenSource, (PVOID*)& pmsvProfile,
		&uProfileLength, &luid, phToken, &limits, &nsSub);

	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		LocalFree(pSidGroup);
		LocalFree(pmsvLogon);
		return FALSE;
	}

	LsaFreeReturnBuffer(pmsvProfile);
	LocalFree(pmsvLogon);

	return TRUE;
}

ULONG InitString(PLSA_STRING plsaString, LPCSTR lpszString)
{
	if (lpszString == NULL) {
		plsaString->Length = 0;
		plsaString->MaximumLength = 0;
		plsaString->Buffer = NULL;
	}
	else {
		plsaString->Length = (USHORT)(lstrlenA(lpszString) * sizeof(CHAR));
		plsaString->MaximumLength = plsaString->Length + sizeof(CHAR);
		plsaString->Buffer = (LPSTR)lpszString;
	}

	return plsaString->Length;
}

ULONG InitUnicodeString(PLSA_UNICODE_STRING plsaString, LPWSTR lpszString)
{
	if (lpszString == NULL) {
		plsaString->Length = 0;
		plsaString->MaximumLength = 0;
		plsaString->Buffer = NULL;
	}
	else {
		plsaString->Length = (USHORT)(lstrlen(lpszString) * sizeof(WCHAR));
		plsaString->MaximumLength = plsaString->Length + sizeof(WCHAR);
		plsaString->Buffer = lpszString;
	}

	return plsaString->Length;
}

void FormatBuffer(LPBYTE* lp, PUNICODE_STRING pString)
{
	if (pString->Buffer != NULL) {
		CopyMemory(*lp, pString->Buffer, pString->Length);
		pString->Buffer = (LPWSTR)* lp;
	}
}

PSID GetGroupSid()
{
	DWORD dwLength;
	PSID  pSid;

	GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_USER_SID, NULL, 0, &dwLength);
	pSid = (PSID)LocalAlloc(LPTR, dwLength);
	GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_USER_SID, pSid, dwLength, &dwLength);

	return pSid;
}

BOOL IsSidEnabled(HANDLE hToken, PSID pSidGroup)
{
	DWORD         i, dwLength;
	PTOKEN_GROUPS pTokenGroups;

	GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength);

	for (i = 0; i < pTokenGroups->GroupCount; i++) {
		if (EqualSid(pTokenGroups->Groups[i].Sid, pSidGroup) && pTokenGroups->Groups[i].Attributes & SE_GROUP_ENABLED) {
			LocalFree(pTokenGroups);
			return TRUE;
		}
	}

	LocalFree(pTokenGroups);

	return FALSE;
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