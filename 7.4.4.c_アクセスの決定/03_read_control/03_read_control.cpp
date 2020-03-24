#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

BOOL CheckSidAndAccessMask(LPCWSTR lpszPath, PSID pSid, DWORD dwAccessMask);
PTOKEN_USER GetTokenUser();
PSID GetUsersSid();

// 特定SIDで識別されるアカウントが特定のアクセスマスクを許可されているか確認

int main()
{
	WCHAR       szDirectoryPath[MAX_PATH];
	BOOL        bResult1, bResult2;
	PTOKEN_USER pTokenUser = GetTokenUser();
	PSID        pUsersSid = GetUsersSid();

	GetCurrentDirectory(MAX_PATH, szDirectoryPath);

	bResult1 = CheckSidAndAccessMask(szDirectoryPath, pTokenUser->User.Sid, READ_CONTROL);
	bResult2 = CheckSidAndAccessMask(szDirectoryPath, pTokenUser->User.Sid, WRITE_DAC);

	int nExitCode = -1;
	if (bResult1 && bResult2) {
		bResult1 = CheckSidAndAccessMask(L"C:\\Program Files", pUsersSid, READ_CONTROL);
		bResult2 = CheckSidAndAccessMask(L"C:\\Program Files", pUsersSid, WRITE_DAC);
		if (bResult1 && !bResult2) {
			printf("想定したアクセス権");
			nExitCode = 0;
		}
		else {
			printf("想定していないアクセス権");
		}
	}
	else
		printf("想定していないアクセス権");

	LocalFree(pTokenUser);
	LocalFree(pUsersSid);

	return nExitCode;
}

BOOL CheckSidAndAccessMask(LPCWSTR lpszPath, PSID pSid, DWORD dwAccessMask)
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
		if (EqualSid(&pAce->SidStart, pSid) && (pAce->Mask & dwAccessMask))
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

PSID GetUsersSid()
{
	PSID  pSid;
	DWORD dwSidSize = MAX_SID_SIZE;
	
	CreateWellKnownSid(WinBuiltinUsersSid, NULL, NULL, &dwSidSize);
	pSid = LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinBuiltinUsersSid, NULL, pSid, &dwSidSize);

	return pSid;
}