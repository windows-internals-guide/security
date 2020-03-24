#include <stdio.h>
#include <windows.h>
#include <authz.h>
#include <strsafe.h>

#pragma comment (lib, "authz.lib")

DWORD ROLE_ARCHITECT[] = { 0x00000501, 0x05000000, 0x00000015, 0x17b85159, 0x255d7266, 0x0b3b6364, 0x00010001 };
DWORD ROLE_LEADER[] = { 0x00000501, 0x05000000, 0x00000015, 0x17b85159, 0x255d7266, 0x0b3b6364, 0x00010002 };

#define DATABASE_READ 0x1
#define DATABASE_WRITE 0x2
#define DATABASE_ALL_ACCESS (DATABASE_READ | DATABASE_WRITE)

struct DATABASE_USER {
	PSID pSid;
	DWORD dwAccessMask;
} database_user[] = {
	{ROLE_ARCHITECT, DATABASE_ALL_ACCESS},
	{ROLE_LEADER, DATABASE_READ}
};

PSECURITY_DESCRIPTOR CreateDatabaseSecurity();
void AddCustomAce(PACL pDacl);
HANDLE CreateClientHandle(PSID pSid);
BOOL CheckAccess(HANDLE hToken, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask);

// ダミーの制限付きSIDでアクセスチェックできるか確認

int main()
{
	DWORD                dwGrantedAccessMask1, dwGrantedAccessMask2, dwGrantedAccessMask3;
	PSECURITY_DESCRIPTOR pSD;
	HANDLE               hTokenArchitect, hTokenLeader;

	pSD = CreateDatabaseSecurity();

	ImpersonateSelf(SecurityImpersonation);
	hTokenArchitect = CreateClientHandle(ROLE_ARCHITECT);
	hTokenLeader = CreateClientHandle(ROLE_LEADER);

	CheckAccess(hTokenArchitect, pSD, DATABASE_ALL_ACCESS, &dwGrantedAccessMask1);
	CheckAccess(hTokenLeader, pSD, DATABASE_READ, &dwGrantedAccessMask2);
	CheckAccess(hTokenLeader, pSD, DATABASE_WRITE, &dwGrantedAccessMask3);

	CloseHandle(hTokenArchitect);
	CloseHandle(hTokenLeader);

	LocalFree(pSD);

	int nExitCode = -1;
	if (dwGrantedAccessMask1 == DATABASE_ALL_ACCESS && dwGrantedAccessMask2 == DATABASE_READ && dwGrantedAccessMask3 == 0) {
		printf("アクセス結果は正しい");
		nExitCode = 0;
	}
	else
		printf("アクセス結果が想定外");

	return nExitCode;
}

PSECURITY_DESCRIPTOR CreateDatabaseSecurity()
{
	DWORD                dwSidSize;
	PSID                 pSidSystem = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	SECURITY_DESCRIPTOR  securityDescriptor;
	PACL                 pDacl = (PACL)LocalAlloc(LPTR, 1024);
	DWORD                dwSDSize = 0;
	PSECURITY_DESCRIPTOR pSD;

	dwSidSize = SECURITY_MAX_SID_SIZE;
	CreateWellKnownSid(WinLocalSystemSid, NULL, pSidSystem, &dwSidSize);

	InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorOwner(&securityDescriptor, pSidSystem, TRUE);
	SetSecurityDescriptorGroup(&securityDescriptor, pSidSystem, TRUE);

	InitializeAcl(pDacl, 1024, ACL_REVISION);
	AddCustomAce(pDacl);
	SetSecurityDescriptorDacl(&securityDescriptor, TRUE, pDacl, FALSE);

	MakeSelfRelativeSD(&securityDescriptor, NULL, &dwSDSize);
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSDSize);
	MakeSelfRelativeSD(&securityDescriptor, pSD, &dwSDSize);

	LocalFree(pSidSystem);
	LocalFree(pDacl);

	return pSD;
}

void AddCustomAce(PACL pDacl)
{
	DWORD dwSidSize;
	PSID  pSidEveryone = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);

	dwSidSize = SECURITY_MAX_SID_SIZE;
	CreateWellKnownSid(WinWorldSid, NULL, pSidEveryone, &dwSidSize);

	// 一見、誰でもアクセスできるように見せかけて
	AddAccessAllowedAce(pDacl, ACL_REVISION, DATABASE_ALL_ACCESS, pSidEveryone);

	AddAccessAllowedAce(pDacl, ACL_REVISION, DATABASE_ALL_ACCESS, ROLE_ARCHITECT);
	AddAccessAllowedAce(pDacl, ACL_REVISION, DATABASE_READ, ROLE_LEADER);

	LocalFree(pSidEveryone);
}

HANDLE CreateClientHandle(PSID pSid)
{
	HANDLE             hToken, hTokenImpersonation;
	SID_AND_ATTRIBUTES sidAttribute;

	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken);

	sidAttribute.Sid = pSid;
	sidAttribute.Attributes = 0;
	CreateRestrictedToken(hToken, 0, 0, NULL, 0, NULL, 1, &sidAttribute, &hTokenImpersonation);

	return hTokenImpersonation;
}

BOOL CheckAccess(HANDLE hToken, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask)
{
	BOOL            bResult, bAccessStatus;
	PRIVILEGE_SET   privilegeSet;
	DWORD           dwPrivilegeSetLength = sizeof(PRIVILEGE_SET);
	GENERIC_MAPPING genericMapping;

	genericMapping.GenericRead = DATABASE_READ;
	genericMapping.GenericWrite = DATABASE_WRITE;
	genericMapping.GenericExecute = 0;
	genericMapping.GenericAll = DATABASE_ALL_ACCESS;

	bResult = AccessCheck(pSD, hToken, dwDesiredAccess, &genericMapping, &privilegeSet, &dwPrivilegeSetLength, pdwGrantedAccessMask, &bAccessStatus);

	return bResult;
}
