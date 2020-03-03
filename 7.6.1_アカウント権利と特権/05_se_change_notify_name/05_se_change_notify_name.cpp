#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

#define DUMMY_DIRECTORY L"directory"
#define DUMMY_FILE L"directory\\file.txt"

BOOL OpenChildObject(BOOL bEnabled);
BOOL CreateDuumyDirectory();
PTOKEN_USER GetTokenUser();
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

// ディレクトリ内のファイルにアクセス許可されていても、ディレクトリそのものにアクセス拒否される場合のファイルアクセスを確認

int main()
{
	if (!CreateDuumyDirectory()) {
		printf("オブジェクト設定に失敗");
		DeleteFile(DUMMY_FILE);
		RemoveDirectory(DUMMY_DIRECTORY);
		return -1;
	}

	int nExitCode = -1;

	if (OpenChildObject(TRUE)) {
		if (!OpenChildObject(FALSE)) {
			printf("SE_CHANGE_NOTIFY_NAMEが無効な事でアクセスに失敗したことを確認");
			nExitCode = 0;
		}
		else
			printf("SE_CHANGE_NOTIFY_NAMEが無効なのにアクセスできた");
	}
	else
		printf("SE_CHANGE_NOTIFY_NAMEが有効なのにアクセスできない。");

	DeleteFile(DUMMY_FILE);
	RemoveDirectory(DUMMY_DIRECTORY);

	return nExitCode;
}

BOOL OpenChildObject(BOOL bEnabled)
{
	EnablePrivilege(SE_CHANGE_NOTIFY_NAME, bEnabled);

	HANDLE hFile = CreateFile(DUMMY_FILE, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	
	CloseHandle(hFile);

	return TRUE;
}

BOOL CreateDuumyDirectory()
{
	CreateDirectory(DUMMY_DIRECTORY, NULL);

	HANDLE hFile = CreateFile(DUMMY_FILE, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hFile);

	PTOKEN_USER pTokenUser = GetTokenUser();
	BYTE        dacl[1024];
	PACL        pDacl = (PACL)dacl;
	
	InitializeAcl(pDacl, 1024, ACL_REVISION);
	AddAccessDeniedAceEx(pDacl, 1, 0, FILE_TRAVERSE, pTokenUser->User.Sid);

	LocalFree(pTokenUser);

	return SetNamedSecurityInfo((LPWSTR)DUMMY_DIRECTORY, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL) == ERROR_SUCCESS;
}

PTOKEN_USER GetTokenUser()
{
	DWORD       dwLength;
	HANDLE      hToken;
	PTOKEN_USER pTokenUser;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);

	return pTokenUser;
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
