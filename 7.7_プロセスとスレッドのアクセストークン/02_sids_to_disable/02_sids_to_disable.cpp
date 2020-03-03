#include <windows.h>
#include <stdio.h>
#include <aclapi.h>

void CreateTokenAndSid(HANDLE* phToken, HANDLE* phTokenRestricted, PSID* ppSidUser, PSID* ppSidAdministrators);
PSECURITY_DESCRIPTOR CreateObjectSecurity(PSID pSidUser, PSID pSidAdministrators, BOOL bDenied);
BOOL CheckAccess(HANDLE hToken, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask);

// 拒否専用のAdministratorsを使用したアクセスチェックを確認

int main(void)
{
	PSID                 pSidUser, pSidAdministrators;
	HANDLE               hToken, hTokenRestricted;
	PSECURITY_DESCRIPTOR pSD, pSDDenied;
	DWORD                dwDesiredAccess, dwGrantedAccessMask1, dwGrantedAccessMask2, dwGrantedAccessMask3, dwGrantedAccessMask4;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください");
		return -1;
	}

	ImpersonateSelf(SecurityImpersonation);
	CreateTokenAndSid(&hToken, &hTokenRestricted, &pSidUser, &pSidAdministrators);

	pSD = CreateObjectSecurity(pSidUser, pSidAdministrators, FALSE);
	pSDDenied = CreateObjectSecurity(pSidUser, pSidAdministrators, TRUE);

	dwDesiredAccess = MAXIMUM_ALLOWED;
	CheckAccess(hToken, pSDDenied, dwDesiredAccess, &dwGrantedAccessMask1);
	CheckAccess(hTokenRestricted, pSDDenied, dwDesiredAccess, &dwGrantedAccessMask2);
	CheckAccess(hToken, pSD, dwDesiredAccess, &dwGrantedAccessMask3);
	CheckAccess(hTokenRestricted, pSD, dwDesiredAccess, &dwGrantedAccessMask4);

	CloseHandle(hToken);
	CloseHandle(hTokenRestricted);
	LocalFree(pSidUser);
	LocalFree(pSidAdministrators);
	LocalFree(pSD);
	LocalFree(pSDDenied);

	int nExitCode = -1;
	if (dwGrantedAccessMask1 == FILE_READ_ACCESS && dwGrantedAccessMask2 == FILE_READ_ACCESS &&
		dwGrantedAccessMask3 == (FILE_READ_ACCESS | FILE_WRITE_ACCESS) && dwGrantedAccessMask4 == FILE_READ_ACCESS) {
		printf("アクセス結果は正しい");
		nExitCode = 0;
	}
	else
		printf("アクセス結果が想定外");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

void CreateTokenAndSid(HANDLE* phToken, HANDLE *phTokenRestricted, PSID* ppSidUser, PSID* ppSidAdministrators)
{
	HANDLE      hToken, hTokenRestricted;
	DWORD       dwSidSize;
	PSID        pSidAdministrators;
	DWORD       dwLength;
	PTOKEN_USER pTokenUser;
	SID_AND_ATTRIBUTES sidsToDisable;

	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken);

	dwSidSize = SECURITY_MAX_SID_SIZE;
	pSidAdministrators = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pSidAdministrators, &dwSidSize);

	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);

	sidsToDisable.Sid = pSidAdministrators;
	sidsToDisable.Attributes = 0;
	CreateRestrictedToken(hToken, 0, 1, &sidsToDisable, 0, NULL, 0, NULL, &hTokenRestricted);

	*phToken = hToken;
	*phTokenRestricted = hTokenRestricted;
	*ppSidAdministrators = pSidAdministrators;

	dwSidSize = GetLengthSid(pTokenUser->User.Sid);
	*ppSidUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSidSize);
	CopySid(dwSidSize, *ppSidUser, pTokenUser->User.Sid);
	LocalFree(pTokenUser);
}

PSECURITY_DESCRIPTOR CreateObjectSecurity(PSID pSidUser, PSID pSidAdministrators, BOOL bDenied)
{
	SECURITY_DESCRIPTOR  securityDescriptor;
	PACL                 pDacl = (PACL)LocalAlloc(LPTR, 1024);
	DWORD                dwSDSize = 0;
	PSECURITY_DESCRIPTOR pSD;

	InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorOwner(&securityDescriptor, pSidUser, TRUE);
	SetSecurityDescriptorGroup(&securityDescriptor, pSidUser, TRUE);

	InitializeAcl(pDacl, 1024, ACL_REVISION);

	if (bDenied) {
		AddAccessDeniedAce(pDacl, ACL_REVISION, FILE_WRITE_ACCESS, pSidAdministrators);
		AddAccessAllowedAce(pDacl, ACL_REVISION, FILE_READ_ACCESS, pSidUser);
	}
	else {
		AddAccessAllowedAce(pDacl, ACL_REVISION, FILE_READ_ACCESS | FILE_WRITE_ACCESS, pSidAdministrators);
		AddAccessAllowedAce(pDacl, ACL_REVISION, FILE_READ_ACCESS, pSidUser);
	}

	SetSecurityDescriptorDacl(&securityDescriptor, TRUE, pDacl, FALSE);

	MakeSelfRelativeSD(&securityDescriptor, NULL, &dwSDSize);
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSDSize);
	MakeSelfRelativeSD(&securityDescriptor, pSD, &dwSDSize);

	LocalFree(pDacl);

	return pSD;
}

BOOL CheckAccess(HANDLE hToken, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask)
{
	BOOL            bResult, bAccessStatus;
	PRIVILEGE_SET   privilegeSet;
	DWORD           dwPrivilegeSetLength = sizeof(PRIVILEGE_SET);
	GENERIC_MAPPING genericMapping;

	genericMapping.GenericRead = FILE_READ_ACCESS;
	genericMapping.GenericWrite = FILE_WRITE_ACCESS;
	genericMapping.GenericExecute = 0;
	genericMapping.GenericAll = FILE_READ_ACCESS | FILE_WRITE_ACCESS;
	MapGenericMask(&dwDesiredAccess, &genericMapping);

	bResult = AccessCheck(pSD, hToken, dwDesiredAccess, &genericMapping, &privilegeSet, &dwPrivilegeSetLength, pdwGrantedAccessMask, &bAccessStatus);
	if (bResult) {
		*pdwGrantedAccessMask &= ~READ_CONTROL & ~WRITE_DAC;
	}

	return bResult;
}