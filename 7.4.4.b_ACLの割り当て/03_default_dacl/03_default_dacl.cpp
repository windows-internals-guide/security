#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

#define DUMMY_DIRECTORY L"directory"
#define DUMMY_FILE L"directory\\file.txt"

BOOL CreateDummyDirectory();
BOOL CreateDummyFile(PACL* ppDacl);
BOOL CompareDefaultDacl(PACL pDacl);

// 独自DACLが設定されたディレクトリの中にファイルを作成した際、デフォルトDACLが適応されることを確認

int main()
{
	if (!CreateDummyDirectory()) {
		printf("DACLの設定に失敗 %d", GetLastError());
		return -1;
	}

	PACL pDacl;
	if (!CreateDummyFile(&pDacl)) {
		printf("デフォルトDACLの取得に失敗 %d", GetLastError());
		RemoveDirectory(DUMMY_DIRECTORY);
		return -1;
	}

	int nExitCode = -1;
	if (CompareDefaultDacl(pDacl)) {
		printf("ファイルのDACLはデフォルトDACLに準拠する");
		nExitCode = 0;
	}
	else
		printf("ファイルのDACLがデフォルトDACLに準拠しない");

	LocalFree(pDacl);
	DeleteFile(DUMMY_FILE);
	RemoveDirectory(DUMMY_DIRECTORY);

	return nExitCode;
}

BOOL CreateDummyDirectory()
{
	CreateDirectory(DUMMY_DIRECTORY, NULL);

	BYTE dacl[1024];
	PACL pDacl = (PACL)dacl;
	BYTE sid[MAX_SID_SIZE];
	PSID pSid = (PSID)sid;
	DWORD dwSidSize = MAX_SID_SIZE;

	CreateWellKnownSid(WinBuiltinUsersSid, NULL, pSid, &dwSidSize);

	InitializeAcl(pDacl, sizeof(dacl), ACL_REVISION);
	DWORD dwAceFlags = 0; // CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
	AddAccessAllowedAceEx(pDacl, ACL_REVISION, dwAceFlags, GENERIC_ALL, pSid);

	return SetNamedSecurityInfo((LPWSTR)DUMMY_DIRECTORY, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL) == ERROR_SUCCESS;
}

BOOL CreateDummyFile(PACL* ppDacl)
{
	HANDLE hFile = CreateFile(DUMMY_FILE, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hFile);

	return GetNamedSecurityInfo(DUMMY_FILE, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, ppDacl, NULL, NULL) == ERROR_SUCCESS;
}

BOOL CompareDefaultDacl(PACL pDacl)
{
	DWORD                i;
	DWORD                dwLength;
	HANDLE               hToken;
	PACCESS_ALLOWED_ACE  pAce;
	PACCESS_ALLOWED_ACE  pAceDefault;
	ACL_SIZE_INFORMATION aclInformation;
	ACL_SIZE_INFORMATION aclInformationDefault;
	PTOKEN_DEFAULT_DACL  pDaclDefault;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenDefaultDacl, NULL, 0, &dwLength);
	pDaclDefault = (PTOKEN_DEFAULT_DACL)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenDefaultDacl, pDaclDefault, dwLength, &dwLength);

	GetAclInformation(pDaclDefault->DefaultDacl, &aclInformationDefault, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);
	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	if (aclInformationDefault.AceCount != aclInformation.AceCount) {
		LocalFree(pDaclDefault);
		CloseHandle(hToken);
		return FALSE;
	}

	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDaclDefault->DefaultDacl, i, (LPVOID*)& pAceDefault);
		GetAce(pDacl, i, (LPVOID*)& pAce);
		if (!EqualSid((PSID)& pAceDefault->SidStart, (PSID)& pAce->SidStart))
			break;
	}

	LocalFree(pDaclDefault);
	CloseHandle(hToken);

	return i == aclInformation.AceCount;
}
