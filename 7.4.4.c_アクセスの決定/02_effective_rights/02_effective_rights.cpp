#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

BOOL TestEffectiveRights(LPCWSTR lpszFilePath, DWORD dwDesiredAccess);
BOOL TestAccessCheck(LPCWSTR lpszFilePath, DWORD dwDesiredAccess);

// GetEffectiveRightsFromAclとAccessCheckの違いを確認

int main()
{
	BOOL    bResult1, bResult2;
	LPCWSTR lpszFilePath = L"C:\\Program Files";
	DWORD   dwDesiredAccess = FILE_GENERIC_WRITE;

	bResult1 = TestEffectiveRights(lpszFilePath, dwDesiredAccess);
	bResult2 = TestAccessCheck(lpszFilePath, dwDesiredAccess);

	int nExitCode = -1;
	if (bResult1 && !bResult2) {
		printf("想定したアクセス結果\n");
		nExitCode = 0;
	}
	else {
		printf("想定しないアクセス結果");
	}

	return nExitCode;
}

BOOL TestEffectiveRights(LPCWSTR lpszFilePath, DWORD dwDesiredAccess)
{
	WCHAR                szAccountName[256];
	DWORD                dwSize;
	PACL                 pDacl;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;
	TRUSTEE              trustee = {0};
	ACCESS_MASK          accessMask;

	if (GetNamedSecurityInfo(lpszFilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return FALSE;

	dwSize = sizeof(szAccountName) / sizeof(WCHAR);
	GetUserName(szAccountName, &dwSize);
	BuildTrusteeWithName(&trustee, szAccountName);

	if (GetEffectiveRightsFromAcl(pDacl, &trustee, &accessMask) != ERROR_SUCCESS) {
		LocalFree(pSecurityDescriptor);
		return FALSE;
	}

	LocalFree(pSecurityDescriptor);

	return accessMask & dwDesiredAccess;
}

BOOL TestAccessCheck(LPCWSTR lpszFilePath, DWORD dwDesiredAccess)
{
	HANDLE               hToken;
	HANDLE               hTokenImpersonatation;
	DWORD                dwGrantedAccess;
	DWORD                dwSize;
	BOOL                 bAccessStatus;
	GENERIC_MAPPING      genericMapping;
	PRIVILEGE_SET        privilegeSet;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	if (GetNamedSecurityInfo(lpszFilePath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
		LocalFree(pSecurityDescriptor);
		return FALSE;
	}

	if (!DuplicateTokenEx(hToken, GENERIC_ALL, NULL, SecurityImpersonation, TokenImpersonation, &hTokenImpersonatation)) {
		CloseHandle(hToken);
		LocalFree(pSecurityDescriptor);
		return FALSE;
	}

	genericMapping.GenericRead = FILE_GENERIC_READ;
	genericMapping.GenericWrite = FILE_GENERIC_WRITE;
	genericMapping.GenericExecute = FILE_GENERIC_EXECUTE;
	genericMapping.GenericAll = FILE_ALL_ACCESS;
	MapGenericMask(&dwDesiredAccess, &genericMapping);

	dwSize = sizeof(PRIVILEGE_SET);
	privilegeSet.PrivilegeCount = 0;
	if (!AccessCheck(pSecurityDescriptor, hTokenImpersonatation, dwDesiredAccess, &genericMapping, &privilegeSet, &dwSize, &dwGrantedAccess, &bAccessStatus)) {
		CloseHandle(hTokenImpersonatation);
		CloseHandle(hToken);
		LocalFree(pSecurityDescriptor);
		return FALSE;
	}

	CloseHandle(hTokenImpersonatation);
	CloseHandle(hToken);
	LocalFree(pSecurityDescriptor);

	return bAccessStatus;
}