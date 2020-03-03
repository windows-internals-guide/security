#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

void SetDacl(LPCWSTR lpszFileName);
BOOL SetNullDacl(LPCWSTR lpszFileName);
BOOL CheckSecurityDescriptor(LPCWSTR lpszFileName);

// OWNER RIGHTSのACEを設定することで、所有者のアクセス権が固定され、DACLの書き換えに失敗することを確認

int main()
{
	HANDLE  hFile;
	LPCWSTR lpszFileName = L"sample.txt";

	hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;
	CloseHandle(hFile);

	SetDacl(lpszFileName);

	if (CheckSecurityDescriptor(lpszFileName)) {
		printf("READ_CONTROLを取り除いているのにセキュリティ記述子を取得できてしまった。");
		DeleteFile(lpszFileName);
		return -1;
	}

	int nExitCode = -1;
	if (!SetNullDacl(lpszFileName)) {
		printf("OWNER RIGHTSによってDACLの書き換えを防いだ。");
		nExitCode = 0;
	}
	else
		printf("DACLを書き換えれてしまった。");

	DeleteFile(lpszFileName);

	return nExitCode;
}

void SetDacl(LPCWSTR lpszFileName)
{
	EXPLICIT_ACCESS explicitAccess[2] = { 0 };
	PACL            pDacl;

	BuildExplicitAccessWithName(&explicitAccess[0], (LPWSTR)L"OWNER RIGHTS", FILE_ALL_ACCESS & ~WRITE_DAC & ~WRITE_OWNER & ~READ_CONTROL, GRANT_ACCESS, 0);
	BuildExplicitAccessWithName(&explicitAccess[1], (LPWSTR)L"SYSTEM", FILE_ALL_ACCESS, GRANT_ACCESS, 0);
	SetEntriesInAcl(sizeof(explicitAccess) / sizeof(explicitAccess[0]), explicitAccess, NULL, &pDacl);

	SetNamedSecurityInfo((LPWSTR)lpszFileName, SE_FILE_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);

	LocalFree(pDacl);
}

BOOL SetNullDacl(LPCWSTR lpszFileName)
{
	return SetNamedSecurityInfo((LPWSTR)lpszFileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
}

BOOL CheckSecurityDescriptor(LPCWSTR lpszFileName)
{
	PACL                 pDacl;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	if (GetNamedSecurityInfo(lpszFileName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return FALSE;

	LocalFree(pSecurityDescriptor);

	return TRUE;
}