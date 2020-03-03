#include <stdio.h>
#include <windows.h>
#include <aclapi.h>

int Check_FileLabel();
int Check_ProcessLabel();
void DumpAce(PACL pSacl);

// オブジェクトに必須ラベルが設定されているか確認

int main()
{
	int nExitCode;

	nExitCode = Check_FileLabel();
	if (nExitCode != -1) {
		nExitCode = Check_ProcessLabel();
	}

	return nExitCode;
}

int Check_FileLabel()
{
	WCHAR                szModuleName[MAX_PATH];
	PACL                 pSacl;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	if (GetNamedSecurityInfo(szModuleName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSacl, &pSecurityDescriptor) != ERROR_SUCCESS) {
		printf("ファイルのセキュリティ記述子の取得に失敗しました。");
		return -1;
	}

	int nExitCode = -1;
	if (pSacl == NULL) {
		printf("ファイルは必須ラベルを持っていません。\n");
		nExitCode = 0;
	}
	else {
		DumpAce(pSacl);
	}

	LocalFree(pSecurityDescriptor);
	
	return nExitCode;
}

int Check_ProcessLabel()
{
	PACL                 pSacl;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;

	if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pSacl, &pSecurityDescriptor) != ERROR_SUCCESS) {
		printf("プロセスのセキュリティ記述子の取得に失敗しました。");
		return -1;
	}

	int nExitCode = -1;
	if (pSacl != NULL) {
		DumpAce(pSacl);
		nExitCode = 0;
	}
	else {
		printf("プロセスは必須ラベルを持っていません。");
	}

	LocalFree(pSecurityDescriptor);
	
	return nExitCode;
}

void DumpAce(PACL pSacl)
{
	PSYSTEM_MANDATORY_LABEL_ACE pAce;

	if (!GetAce(pSacl, 0, (LPVOID *)&pAce)) {
		return;
	}

	DWORD dwRid = *GetSidSubAuthority(&pAce->SidStart, 0);
	CHAR  szName[256];

	if (dwRid == SECURITY_MANDATORY_UNTRUSTED_RID)
		strcpy_s(szName, "Untrusted");
	else if (dwRid == SECURITY_MANDATORY_LOW_RID)
		strcpy_s(szName, "Low");
	else if (dwRid == SECURITY_MANDATORY_MEDIUM_RID)
		strcpy_s(szName, "Medium");
	else if (dwRid == SECURITY_MANDATORY_HIGH_RID)
		strcpy_s(szName, "High");
	else if (dwRid == SECURITY_MANDATORY_SYSTEM_RID)
		strcpy_s(szName, "System");
	else
		;

	printf("mask %d, level %s\n", pAce->Mask, szName);
}
