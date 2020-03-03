#include <stdio.h>
#include <windows.h>
#include <authz.h>
#include <strsafe.h>

#pragma comment (lib, "authz.lib")

#define ROLE_ARCHITECT (LPWSTR)L"Architect"
#define ROLE_LEADER (LPWSTR)L"Leader"

#define DATABASE_READ 0x1
#define DATABASE_WRITE 0x2
#define DATABASE_ALL_ACCESS (DATABASE_READ | DATABASE_WRITE)

struct DATABASE_USER {
	PWSTR pszName;
	DWORD dwAccessMask;
} database_user[] = {
	{ROLE_ARCHITECT, DATABASE_ALL_ACCESS},
	{ROLE_LEADER, DATABASE_READ}
};

PSECURITY_DESCRIPTOR CreateDatabaseSecurity();
void AddCustomAce(PACL pDacl);
AUTHZ_CLIENT_CONTEXT_HANDLE CreateClientContextHandle(PWSTR pszName, AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager);
PAUTHZ_SECURITY_ATTRIBUTE_V1 GetSecurityAttribute(PWSTR pszName);
BOOL CheckAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask);

// 属性名でアクセスチェックが成立する確認

int main()
{
	DWORD                         dwGrantedAccessMask1, dwGrantedAccessMask2, dwGrantedAccessMask3;
	PSECURITY_DESCRIPTOR          pSD;
	AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager;
	AUTHZ_CLIENT_CONTEXT_HANDLE   hAuthzArchitect, hAuthzLeader;

	pSD = CreateDatabaseSecurity();

	AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, NULL, NULL, NULL, L"", &hAuthzResourceManager);
	hAuthzArchitect = CreateClientContextHandle(ROLE_ARCHITECT, hAuthzResourceManager);
	hAuthzLeader = CreateClientContextHandle(ROLE_LEADER, hAuthzResourceManager);

	CheckAccess(hAuthzArchitect, pSD, DATABASE_ALL_ACCESS, &dwGrantedAccessMask1);
	CheckAccess(hAuthzLeader, pSD, DATABASE_READ, &dwGrantedAccessMask2);
	CheckAccess(hAuthzLeader, pSD, DATABASE_WRITE, &dwGrantedAccessMask3);

	AuthzFreeContext(hAuthzArchitect);
	AuthzFreeContext(hAuthzLeader);
	AuthzFreeResourceManager(hAuthzResourceManager);

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
	DWORD dwLength;
	PSID  pSidEveryone = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	WCHAR szCondition[256];
	WCHAR szFormat[] = L"(exists %s)";

	dwSidSize = SECURITY_MAX_SID_SIZE;
	CreateWellKnownSid(WinWorldSid, NULL, pSidEveryone, &dwSidSize);

	StringCchPrintf(szCondition, ARRAYSIZE(szCondition), szFormat, ROLE_ARCHITECT);
	AddConditionalAce(pDacl, ACL_REVISION, 0, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, DATABASE_ALL_ACCESS, pSidEveryone, szCondition, &dwLength);

	StringCchPrintf(szCondition, ARRAYSIZE(szCondition), szFormat, ROLE_LEADER);
	AddConditionalAce(pDacl, ACL_REVISION, 0, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, DATABASE_READ, pSidEveryone, szCondition, &dwLength);

	LocalFree(pSidEveryone);
}

PAUTHZ_SECURITY_ATTRIBUTE_V1 GetSecurityAttribute(PWSTR pszName)
{
	PAUTHZ_SECURITY_ATTRIBUTE_V1 pAuthzSecurity;
	PWSTR                        pszRef;
	PLONG64                      pLong64Ref;
	DWORD                        dwAttributeCount = 1;
	DWORD                        dwStringSize = (lstrlen(pszName) + 1) * sizeof(WCHAR);
	DWORD                        dwTotalSize = (dwAttributeCount * sizeof(AUTHZ_SECURITY_ATTRIBUTE_V1)) + dwStringSize + sizeof(LONG64);

	pAuthzSecurity = (PAUTHZ_SECURITY_ATTRIBUTE_V1)LocalAlloc(LPTR, dwTotalSize);
	pszRef = (LPWSTR)(pAuthzSecurity + sizeof(AUTHZ_SECURITY_ATTRIBUTE_V1));
	StringCchCopy(pszRef, dwStringSize, pszName);
	pLong64Ref = (PLONG64)(pAuthzSecurity + sizeof(AUTHZ_SECURITY_ATTRIBUTE_V1) + dwStringSize);
	*pLong64Ref = 0;

	pAuthzSecurity->pName = (LPWSTR)pszRef;
	pAuthzSecurity->ValueType = AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64;
	pAuthzSecurity->Reserved = 0;
	pAuthzSecurity->Flags = 0;
	pAuthzSecurity->ValueCount = 1;
	pAuthzSecurity->Values.pInt64 = pLong64Ref;

	return pAuthzSecurity;
}

AUTHZ_CLIENT_CONTEXT_HANDLE CreateClientContextHandle(PWSTR pszName, AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager)
{
	DWORD                       dwSidSize;
	PSID                        pSidEveryone;
	AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext;
	LUID                        identifier = { 0 };

	dwSidSize = SECURITY_MAX_SID_SIZE;
	pSidEveryone = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinWorldSid, NULL, pSidEveryone, &dwSidSize);

	AuthzInitializeContextFromSid(0, pSidEveryone, hAuthzResourceManager, NULL, identifier, NULL, &hAuthzContext);

	LocalFree(pSidEveryone);

	AUTHZ_SECURITY_ATTRIBUTE_OPERATION operation = AUTHZ_SECURITY_ATTRIBUTE_OPERATION_ADD;
	AUTHZ_SECURITY_ATTRIBUTES_INFORMATION authzInfo;
	authzInfo.Version = AUTHZ_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1;
	authzInfo.Reserved = 0;
	authzInfo.AttributeCount = 1;
	authzInfo.Attribute.pAttributeV1 = (PAUTHZ_SECURITY_ATTRIBUTE_V1)GetSecurityAttribute(pszName);
	AuthzModifySecurityAttributes(hAuthzContext, &operation, &authzInfo);

	return hAuthzContext;
}

BOOL CheckAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask)
{
	BOOL                 bResult;
	AUTHZ_ACCESS_REQUEST request = { 0 };
	AUTHZ_ACCESS_REPLY   reply = { 0 };

	request.DesiredAccess = dwDesiredAccess;
	request.PrincipalSelfSid = NULL;
	request.ObjectTypeList = NULL;
	request.ObjectTypeListLength = 0;
	request.OptionalArguments = &dwDesiredAccess;

	reply.ResultListLength = 1;
	reply.SaclEvaluationResults = NULL;
	reply.GrantedAccessMask = (PACCESS_MASK)LocalAlloc(LPTR, sizeof(ACCESS_MASK) * reply.ResultListLength);
	reply.Error = (PDWORD)LocalAlloc(LPTR, sizeof(DWORD) * reply.ResultListLength);

	bResult = AuthzAccessCheck(0, hAuthzContext, &request, NULL, pSD, NULL, 0, &reply, NULL);
	if (bResult)
		* pdwGrantedAccessMask = reply.GrantedAccessMask[0];
	else
		*pdwGrantedAccessMask = 0;

	LocalFree(reply.GrantedAccessMask);
	LocalFree(reply.Error);

	return bResult;
}
