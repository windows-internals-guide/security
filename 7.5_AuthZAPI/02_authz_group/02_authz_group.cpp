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
AUTHZ_CLIENT_CONTEXT_HANDLE CreateClientHandle(PVOID pArgs, AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager);
BOOL CheckAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask);
BOOL CheckCachedAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask);
BOOL CALLBACK AuthzAccessCheckCallback(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext, PACE_HEADER pAce, PVOID pArgs, PBOOL pbAceApplicable);
BOOL CALLBACK AuthzComputeGroupsCallback(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext, PVOID Args, PSID_AND_ATTRIBUTES* pSidAttrArray, PDWORD pSidCount, PSID_AND_ATTRIBUTES* pRestrictedSidAttrArray, PDWORD pRestrictedSidCount);
void CALLBACK AuthzFreeGroupsCallback(PSID_AND_ATTRIBUTES pSidAttrArray);

// Authz APIのキャッシュ機能でアクセスチェックできるか確認

int main()
{
	DWORD                         dwGrantedAccessMask1, dwGrantedAccessMask2, dwGrantedAccessMask3;
	PSECURITY_DESCRIPTOR          pSD;
	AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager;
	AUTHZ_CLIENT_CONTEXT_HANDLE   hAuthzArchitect, hAuthzLeader;

	pSD = CreateDatabaseSecurity();

	AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, AuthzAccessCheckCallback, AuthzComputeGroupsCallback, AuthzFreeGroupsCallback, L"", &hAuthzResourceManager);
	hAuthzArchitect = CreateClientHandle(ROLE_ARCHITECT, hAuthzResourceManager);
	hAuthzLeader = CreateClientHandle(ROLE_LEADER, hAuthzResourceManager);

	CheckAccess(hAuthzArchitect, pSD, DATABASE_ALL_ACCESS, &dwGrantedAccessMask1);
	CheckAccess(hAuthzLeader, pSD, DATABASE_READ, &dwGrantedAccessMask2);
	CheckCachedAccess(hAuthzLeader, pSD, DATABASE_WRITE, &dwGrantedAccessMask3);

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
	DWORD                dwSidSize;
	PSID                 pSidEveryone = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	PACCESS_ALLOWED_ACE  pAce;

	dwSidSize = SECURITY_MAX_SID_SIZE;
	CreateWellKnownSid(WinWorldSid, NULL, pSidEveryone, &dwSidSize);

	AddAccessAllowedAce(pDacl, ACL_REVISION, DATABASE_ALL_ACCESS, pSidEveryone);
	GetAce(pDacl, 0, (LPVOID*)& pAce);
	pAce->Header.AceType = ACCESS_ALLOWED_CALLBACK_ACE_TYPE;

	LocalFree(pSidEveryone);
}

AUTHZ_CLIENT_CONTEXT_HANDLE CreateClientHandle(PVOID pArgs, AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager)
{
	DWORD                       dwSidSize;
	PSID                        pSidEveryone;
	AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext;
	LUID                        identifier = { 0 };

	dwSidSize = SECURITY_MAX_SID_SIZE;
	pSidEveryone = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinWorldSid, NULL, pSidEveryone, &dwSidSize);

	AuthzInitializeContextFromSid(0, pSidEveryone, hAuthzResourceManager, NULL, identifier, pArgs, &hAuthzContext);

	LocalFree(pSidEveryone);

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

BOOL CheckCachedAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzContext, PSECURITY_DESCRIPTOR pSD, DWORD dwDesiredAccess, PDWORD pdwGrantedAccessMask)
{
	BOOL                 bResult;
	AUTHZ_ACCESS_REQUEST request = { 0 };
	AUTHZ_ACCESS_REPLY   reply = { 0 };
	AUTHZ_ACCESS_CHECK_RESULTS_HANDLE hCache;

	request.DesiredAccess = MAXIMUM_ALLOWED;
	request.PrincipalSelfSid = NULL;
	request.ObjectTypeList = NULL;
	request.ObjectTypeListLength = 0;
	request.OptionalArguments = &request.DesiredAccess;

	reply.ResultListLength = 1;
	reply.SaclEvaluationResults = NULL;
	reply.GrantedAccessMask = (PACCESS_MASK)LocalAlloc(LPTR, sizeof(ACCESS_MASK) * reply.ResultListLength);
	reply.Error = (PDWORD)LocalAlloc(LPTR, sizeof(DWORD) * reply.ResultListLength);

	bResult = AuthzAccessCheck(0, hAuthzContext, &request, NULL, pSD, NULL, 0, &reply, &hCache);
	if (bResult) {
		request.DesiredAccess = dwDesiredAccess;
		bResult = AuthzCachedAccessCheck(0, hCache, &request, NULL, &reply);
		*pdwGrantedAccessMask = reply.GrantedAccessMask[0];
		AuthzFreeHandle(hCache);
	}

	LocalFree(reply.GrantedAccessMask);
	LocalFree(reply.Error);

	return bResult;
}

BOOL CALLBACK AuthzAccessCheckCallback(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext, PACE_HEADER pAce, PVOID pArgs, PBOOL pbAceApplicable)
{
	int           i;
	int           nConunt = sizeof(database_user) / sizeof(database_user[0]);
	PTOKEN_GROUPS pTokenGroups;
	DWORD         dwTokenGroupsSize;
	DWORD         dwDesiredAccess = *((PDWORD)pArgs);
	DWORD         dwAccessMask = *(PDWORD)((PBYTE)pAce + sizeof(ACE_HEADER));
	DWORD         dwFlags = dwDesiredAccess & dwAccessMask;

	AuthzGetInformationFromContext(hAuthzClientContext, AuthzContextInfoGroupsSids, 0, &dwTokenGroupsSize, NULL);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwTokenGroupsSize);
	AuthzGetInformationFromContext(hAuthzClientContext, AuthzContextInfoGroupsSids, dwTokenGroupsSize, &dwTokenGroupsSize, pTokenGroups);

	for (i = 0; i < nConunt; i++) {
		if (EqualSid(pTokenGroups->Groups[0].Sid, database_user[i].pSid) && dwFlags & database_user[i].dwAccessMask) {
			*pbAceApplicable = TRUE;
			break;
		}
	}
	
	LocalFree(pTokenGroups);

	return TRUE;
}

BOOL CALLBACK AuthzComputeGroupsCallback(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext, PVOID Args,
	PSID_AND_ATTRIBUTES* pSidAttrArray, PDWORD pSidCount, PSID_AND_ATTRIBUTES* pRestrictedSidAttrArray, PDWORD pRestrictedSidCount)
{
	*pSidCount = 1;
	*pSidAttrArray = (PSID_AND_ATTRIBUTES)(PSID)LocalAlloc(LPTR, sizeof(SID_AND_ATTRIBUTES));

	(*pSidAttrArray)[0].Sid = ((PSID)Args);
	(*pSidAttrArray)[0].Attributes = SE_GROUP_ENABLED;

	*pRestrictedSidCount = 0;
	*pRestrictedSidAttrArray = NULL;

	return TRUE;
}

void CALLBACK AuthzFreeGroupsCallback(PSID_AND_ATTRIBUTES pSidAttrArray)
{
	if (pSidAttrArray != NULL)
		LocalFree(pSidAttrArray);
}
