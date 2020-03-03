#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

void SetDacl(LPCWSTR lpszFileName);
BOOL SetNullDacl(LPCWSTR lpszFileName);
BOOL CheckOwner(LPCWSTR lpszFileName);
PTOKEN_USER GetTokenUser();

// 現在ユーザーにWRITE_DACを許可しないACEを設定したのに、所有者であるためDACLの書き換えに成功する事を確認

int main()
{
	HANDLE  hFile;
	LPCWSTR lpszFileName = L"sample.txt";

	hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;
	CloseHandle(hFile);

	
	SetDacl(lpszFileName);
	
	if (!CheckOwner(lpszFileName)) {
		printf("所有者として正しくない");
		return -1;
	}

	int nExitCode = -1;

	if (SetNullDacl(lpszFileName)) {
		printf("DACLを書き換えれた。");
		nExitCode = 0;
	}
	else
		printf("DACLの書き換えの失敗した。");

	DeleteFile(lpszFileName);

	return nExitCode;
}

BOOL CheckOwner(LPCWSTR lpszFileName)
{
	PSID                 pSidOwner;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	if (GetNamedSecurityInfo(lpszFileName, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pSidOwner, NULL, NULL, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return FALSE;

	PTOKEN_USER pTokenUser = GetTokenUser();

	if (!EqualSid(pTokenUser->User.Sid, pSidOwner)) {
		LocalFree(pSecurityDescriptor);
		LocalFree(pTokenUser);
		return FALSE;
	}

	BOOL   bResult = FALSE;
	HANDLE hFile = CreateFile(lpszFileName, WRITE_DAC, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		bResult = TRUE;
	}
	
	LocalFree(pSecurityDescriptor);
	LocalFree(pTokenUser);

	return bResult;
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

	CloseHandle(hToken);

	return pTokenUser;
}

void SetDacl(LPCWSTR lpszFileName)
{
	WCHAR           szAccountName[256];
	DWORD           dwSize;
	EXPLICIT_ACCESS explicitAccess[2] = {0};
	PACL            pDacl;
	
	dwSize = sizeof(szAccountName) / sizeof(WCHAR);
	GetUserName(szAccountName, &dwSize);
	BuildExplicitAccessWithName(&explicitAccess[0], szAccountName, FILE_ALL_ACCESS & ~WRITE_DAC & ~WRITE_OWNER, GRANT_ACCESS, 0);
	BuildExplicitAccessWithName(&explicitAccess[1], (LPWSTR)L"SYSTEM", FILE_ALL_ACCESS, GRANT_ACCESS, 0);
	SetEntriesInAcl(sizeof(explicitAccess) / sizeof(explicitAccess[0]), explicitAccess, NULL, &pDacl);
	
	SetNamedSecurityInfo((LPWSTR)lpszFileName, SE_FILE_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);

	LocalFree(pDacl);
}

BOOL SetNullDacl(LPCWSTR lpszFileName)
{
	return SetNamedSecurityInfo((LPWSTR)lpszFileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
}