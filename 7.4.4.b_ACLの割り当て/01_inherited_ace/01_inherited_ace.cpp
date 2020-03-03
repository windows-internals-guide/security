#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

BOOL IsInherited(LPWSTR lpszPath, DWORD dwFlags);
void PrintAce(LPWSTR lpszPath);

// デフォルトのディレクトリとexeファイルのDACLを調べ、継承ACEで構成されていることを確認

int main()
{
	WCHAR szDirectoryPath[MAX_PATH];
	WCHAR szFilePath[MAX_PATH];
	BOOL  bResult1, bResult2;

	GetCurrentDirectory(MAX_PATH, szDirectoryPath);
	GetModuleFileName(NULL, szFilePath, MAX_PATH);

	bResult1 = IsInherited(szDirectoryPath, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE);
	bResult2 = IsInherited(szFilePath, INHERITED_ACE);

	int nExitCode = -1;
	if (bResult1 && bResult2) {
		printf("ACEを正常に継承している");
#if 0
		printf("\n");
		PrintAce(szDirectoryPath);
		PrintAce(szFilePath);
#endif
		nExitCode = 0;
	}
	else {
		printf("ACEを正常に継承していない");
	}

	return nExitCode;
}

BOOL IsInherited(LPWSTR lpszPath, DWORD dwFlags)
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
		if (!(pAce->Header.AceFlags & dwFlags))
			break;
	}

	LocalFree(pSecurityDescriptor);

	return i == aclInformation.AceCount;
}

void PrintAce(LPWSTR lpszPath)
{
	DWORD                i;
	PACL                 pDacl;
	PACCESS_ALLOWED_ACE  pAce;
	ACL_SIZE_INFORMATION aclInformation;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	printf("-------------------\n");

	if (GetNamedSecurityInfo(lpszPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor) != ERROR_SUCCESS) {
		return;
	}

	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		printf("%#08x \n", pAce->Header.AceFlags);

		if (pAce->Header.AceFlags & OBJECT_INHERIT_ACE)
			printf("OBJECT_INHERIT_ACE \n");
		if (pAce->Header.AceFlags & CONTAINER_INHERIT_ACE)
			printf("CONTAINER_INHERIT_ACE \n");
		if (pAce->Header.AceFlags & NO_PROPAGATE_INHERIT_ACE)
			printf("NO_PROPAGATE_INHERIT_ACE \n");
		if (pAce->Header.AceFlags & INHERIT_ONLY_ACE)
			printf("INHERIT_ONLY_ACE \n");
		if (pAce->Header.AceFlags & INHERITED_ACE)
			printf("INHERITED_ACE \n");
	}

	LocalFree(pSecurityDescriptor);
}