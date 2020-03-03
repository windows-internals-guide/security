#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

#define DUMMY_DIRECTORY1 L"directory1"
#define DUMMY_DIRECTORY2 L"directory2"

#define DUMMY_FILE1 L"directory1\\file1.txt"
#define DUMMY_FILE2 L"directory2\\file2.txt"

PACL CreateDacl(PSID pSid, BOOL bProtected);
BOOL CreateDuumyDirectory(LPCWSTR lpszFileName, PACL pDacl, BOOL bProtected);
BOOL IsSidIncluded(LPCWSTR lpszFileName, PSID pSid, BOOL bProtected);
BOOL CheckChildObject(LPCWSTR lpszFileName, PSID pSid);
	
// PROTECTED_DACL_SECURITY_INFORMATIONで既存DACLとのマージを防げる(継承を防げる)ことと、マージ発生時にSIDが先頭配置なことの確認
// さらにACEが継承フラグを持つことで、子オブジェクトにACEが伝達されることを確認。

int main()
{
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID  pSid = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinAuthenticatedUserSid, NULL, pSid, &dwSidSize);

	PACL pDacl1 = CreateDacl(pSid, TRUE);
	PACL pDacl2 = CreateDacl(pSid, FALSE);

	CreateDuumyDirectory(DUMMY_DIRECTORY1, pDacl1, TRUE);
	CreateDuumyDirectory(DUMMY_DIRECTORY2, pDacl2, FALSE);

	BOOL bResult1 = IsSidIncluded(DUMMY_DIRECTORY1, pSid, TRUE);
	BOOL bResult2 = IsSidIncluded(DUMMY_DIRECTORY2, pSid, FALSE);
	int nExitCode = -1;
	if (bResult1 && bResult2) {
		bResult1 = CheckChildObject(DUMMY_FILE1, pSid);
		bResult2 = CheckChildObject(DUMMY_FILE2, pSid);
		if (bResult1 && !bResult2) {
			printf("ACEは正しく設定されている");
			nExitCode = 0;
		}
		else {
			printf("継承の挙動が正しくない");
		}
	}
	else {
		printf("ACEが正しくセットされていない");
	}

	LocalFree(pSid);
	LocalFree(pDacl1);
	LocalFree(pDacl2);

	RemoveDirectory(DUMMY_DIRECTORY1);
	RemoveDirectory(DUMMY_DIRECTORY2);

	return nExitCode;
}

BOOL CreateDuumyDirectory(LPCWSTR lpszDirectoryPath, PACL pDacl, BOOL bProtected)
{
	CreateDirectory(lpszDirectoryPath, NULL);

	SECURITY_INFORMATION securityInfo = DACL_SECURITY_INFORMATION;
	if (bProtected)
		securityInfo |= PROTECTED_DACL_SECURITY_INFORMATION;

	SetNamedSecurityInfo((LPWSTR)lpszDirectoryPath, SE_FILE_OBJECT, securityInfo, NULL, NULL, pDacl, NULL);

	return TRUE;
}

BOOL IsSidIncluded(LPCWSTR lpszDirectoryPath, PSID pSid, BOOL bProtected)
{
	PACL pDacl;

	if (GetNamedSecurityInfo(lpszDirectoryPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, NULL) != ERROR_SUCCESS)
		return FALSE;

	ACL_SIZE_INFORMATION aclInformation;
	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	PACCESS_ALLOWED_ACE pAce;

	GetAce(pDacl, 0, (LPVOID*)& pAce);
	if (!EqualSid((PSID)& pAce->SidStart, pSid)) {
		LocalFree(pDacl);
		return FALSE;
	}

	if (pAce->Header.AceFlags & INHERITED_ACE) {
		LocalFree(pDacl);
		return FALSE;
	}

	if (bProtected && aclInformation.AceCount == 1) {
		LocalFree(pDacl);
		return FALSE;
	}

	LocalFree(pDacl);

	return TRUE;
}
	
PACL CreateDacl(PSID pSid, BOOL bProtected)
{
	DWORD dwDaclSize = 1024;
	PACL  pDacl = (PACL)LocalAlloc(LPTR, dwDaclSize);
	InitializeAcl(pDacl, dwDaclSize, ACL_REVISION);

	DWORD dwAceFlags = bProtected ? CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE : 0;

	AddAccessAllowedAceEx(pDacl, ACL_REVISION, dwAceFlags, GENERIC_ALL, pSid);

	return pDacl;
}

BOOL CheckChildObject(LPCWSTR lpszFileName, PSID pSid)
{
	HANDLE hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hFile);

	PACL pDacl;

	if (GetNamedSecurityInfo(lpszFileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, NULL) != ERROR_SUCCESS) {
		DeleteFile(lpszFileName);
		return FALSE;
	}

	DWORD                i;
	PACCESS_ALLOWED_ACE  pAce;
	ACL_SIZE_INFORMATION aclInformation;

	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		if (EqualSid((PSID)& pAce->SidStart, pSid) && pAce->Header.AceFlags & INHERITED_ACE) {
			break;
		}
	}

	LocalFree(pDacl);

	DeleteFile(lpszFileName);

	return i != aclInformation.AceCount;
}
