#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

PTOKEN_USER GetTokenUser();
BOOL CheckUser(LPWSTR lpszPath, PSID pSidUser);

// exeファイルのDACLを調べ、現在ユーザーを含むか確認

int main()
{
	WCHAR       szFilePath[MAX_PATH];
	PTOKEN_USER pTokenUser;

	GetModuleFileName(NULL, szFilePath, MAX_PATH);
	pTokenUser = GetTokenUser();

	int nExitCode = -1;
	if (CheckUser(szFilePath, pTokenUser->User.Sid)) {
		printf("現在ユーザーを許可するACEが存在");
		nExitCode = 0;
	}
	else {
		printf("現在ユーザーを許可するACEが存在しない");
	}

	LocalFree(pTokenUser);

	return nExitCode;
}

BOOL CheckUser(LPWSTR lpszPath, PSID pSidUser)
{
	DWORD                i;
	PACL                 pDacl;
	PACCESS_ALLOWED_ACE  pAce;
	ACL_SIZE_INFORMATION aclInformation;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	if (GetNamedSecurityInfo(lpszPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return FALSE;

	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		if (EqualSid((PSID)&pAce->SidStart, pSidUser))
			break;
	}

	LocalFree(pSecurityDescriptor);

	return i != aclInformation.AceCount;
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