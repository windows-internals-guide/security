#define INITGUID
#include <windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <shlobj.h>
#include <aclapi.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

BOOL SetSaclToTestFile(LPWSTR lpszFilePath);
BOOL AccessTestFile(LPWSTR lpszFilePath);
void DeleteTestFile(LPWSTR lpszFilePath);
int GeSecurityLogCount();
void SetAuditPolicy(BOOL bSet);
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return -1;
	}
	
	if (!EnablePrivilege(SE_SECURITY_NAME, TRUE)) {
		printf("SE_SECURITY_NAME特権の有効に失敗しました。");
		return -1;
	}
	
	BOOL  bResult;
	WCHAR szFilePath[] = L"test.txt";
	
	if (!SetSaclToTestFile(szFilePath)) {
		printf("ファイルへのSACL設定に失敗した");
		DeleteTestFile(szFilePath);
		return -1;
	}
	
	if (AccessTestFile(szFilePath)) {
		printf("監査ポリシーを有効にしていないのに監査の効果を確認してしまった");
		DeleteTestFile(szFilePath);
		return -1;
	}
	
	SetAuditPolicy(TRUE);
	bResult = AccessTestFile(szFilePath);
	SetAuditPolicy(FALSE);
	
	DeleteTestFile(szFilePath);
	
	int nExitCode = -1;
	if (bResult) {
		printf("Securityイベントログの総数の変更を確認した");
		nExitCode = 0;
	}
	else
		printf("監査の効果(Securityイベントログへの書き込み)を確認できない。");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL SetSaclToTestFile(LPWSTR lpszFilePath)
{
	HANDLE      hFile;
	PACL        pSacl;
	DWORD       dwSaclSize;
	HANDLE      hToken;
	PTOKEN_USER pTokenUser;
	DWORD       dwLength;
	BOOL        bResult = FALSE;

	hFile = CreateFile(lpszFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	CloseHandle(hFile);

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);

	dwSaclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pTokenUser->User.Sid) - sizeof(DWORD);
	pSacl = (PACL)LocalAlloc(LPTR, dwSaclSize);
	InitializeAcl(pSacl, dwSaclSize, ACL_REVISION);

	if (AddAuditAccessAce(pSacl, ACL_REVISION, GENERIC_ALL, pTokenUser->User.Sid, TRUE, TRUE)) {
		if (SetNamedSecurityInfo(lpszFilePath, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl) == ERROR_SUCCESS)
			bResult = TRUE;
	}

	LocalFree(pSacl);

	return bResult;
}

BOOL AccessTestFile(LPWSTR lpszFilePath)
{
	int    nCount1, nCount2;
	CHAR   szBuf[] = "text";
	DWORD  dwWriteByte;
	HANDLE hFile;

	nCount1 = GeSecurityLogCount();

	hFile = CreateFile(lpszFilePath, FILE_WRITE_ACCESS, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, szBuf, sizeof(szBuf), &dwWriteByte, NULL);
	CloseHandle(hFile);

	Sleep(1000);

	nCount2 = GeSecurityLogCount();

	return nCount1 != nCount2;
}

void DeleteTestFile(LPWSTR lpszFilePath)
{
	DeleteFile(lpszFilePath);
}

void SetAuditPolicy(BOOL bSet)
{
	AUDIT_POLICY_INFORMATION auditPolicy;
	ULONG uInfo = bSet ? POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_NONE : POLICY_AUDIT_EVENT_NONE;

	auditPolicy.AuditSubCategoryGuid = Audit_ObjectAccess_FileSystem;
	auditPolicy.AuditingInformation = uInfo;

	AuditSetSystemPolicy(&auditPolicy, 1);
}

#define QUERY \
    L"<QueryList>" \
    L"  <Query Path='Microsoft-Windows-Security-Auditing'>" \
    L"    <Select Path='Security'>Event/System[EventID=4663]</Select>" \
    L"  </Query>" \
    L"</QueryList>"

int GeSecurityLogCount()
{
	EVT_HANDLE hQuery, hEvents[10];
	DWORD dwReturned, dwTotal = 0;

	hQuery = EvtQuery(NULL, 0, QUERY, EvtQueryChannelPath | EvtQueryReverseDirection);
	if (hQuery == NULL) {
		return 0;
	}

	for (;;) {
		if (!EvtNext(hQuery, 10, hEvents, INFINITE, 0, &dwReturned))
			break;
		dwTotal += dwReturned;
	}

	return dwTotal;
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