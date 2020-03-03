#include <windows.h>
#include <aclapi.h>
#include <stdio.h>

BOOL SetSystemLabel(LPCWSTR lpszFileName);
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

// SE_RELABEL_NAMEの有効化で整合レベルを引き上げれることを確認

int main()
{
	HANDLE  hFile;
	LPCWSTR lpszFileName = L"sample.txt";
	
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("特権有効のため管理者として実行してください。");
		return -1;
	}

	hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;
	CloseHandle(hFile);

	if (SetSystemLabel(lpszFileName)) {
		printf("特権を有効にしていないのにシステムラベルを設定できた");
		DeleteFile(lpszFileName);
		return -1;
	}

	if (!EnablePrivilege(SE_RELABEL_NAME, TRUE)) {
		return -1;
	}

	int nExitCode = -1;
	if (SetSystemLabel(lpszFileName)) {
		printf("システムラベルを設定できた");
		nExitCode = 0;
	}
	else
		printf("システムラベルを設定できなかった");

	DeleteFile(lpszFileName);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

BOOL SetSystemLabel(LPCWSTR lpszFileName)
{
	BYTE  sacl[1024];
	PACL  pSacl = (PACL)sacl;
	BYTE  sid[SECURITY_MAX_SID_SIZE];
	PSID  pSid = (PSID)sid;
	DWORD dwSidSize;

	InitializeAcl(pSacl, 1024, ACL_REVISION);
	
	dwSidSize = SECURITY_MAX_SID_SIZE;
	CreateWellKnownSid(WinSystemLabelSid, NULL, pSid, &dwSidSize);

	if (!AddMandatoryAce(pSacl, ACL_REVISION, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, pSid)) {
		return FALSE;
	}

	return SetNamedSecurityInfo((LPWSTR)lpszFileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl) == ERROR_SUCCESS;
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