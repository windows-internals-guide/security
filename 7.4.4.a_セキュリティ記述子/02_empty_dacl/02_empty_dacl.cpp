#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

#define MUTEX_NAME L"my_mutex"

BOOL TestEmptyDacl();
BOOL TestNullDacl();
BOOL TestMutexOpen();
BOOL SetUntrustedLabel();

// 空のDACLにはアクセスできず、NULL DACLは誰でもアクセスできることを確認

int main()
{
	BOOL   bResult1, bResult2;
	HANDLE hMutex;

	hMutex = CreateMutex(NULL, TRUE, MUTEX_NAME);
	if (hMutex == NULL)
		return -1;
	
	bResult1 = TestEmptyDacl();
	bResult2 = TestNullDacl();

	int nExitCode = -1;
	if (!bResult1 && bResult2) {
		printf("空のDACLにはアクセス失敗、NULL DACLにはアクセス成功");
		nExitCode = 0;
	}
	else
		printf("想定しないアクセス結果");

	CloseHandle(hMutex);

	return nExitCode;
}

BOOL TestEmptyDacl()
{
	BYTE dacl[1024];
	PACL pDacl = (PACL)dacl;

	InitializeAcl(pDacl, 1024, ACL_REVISION);

	SetNamedSecurityInfo((LPWSTR)MUTEX_NAME, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);

	return TestMutexOpen();
}

BOOL TestNullDacl()
{
	SetNamedSecurityInfo((LPWSTR)MUTEX_NAME, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);

	SetUntrustedLabel();

	ImpersonateAnonymousToken(GetCurrentThread());

	return TestMutexOpen();
}

BOOL TestMutexOpen()
{
	HANDLE hMutex = OpenMutex(SYNCHRONIZE, FALSE, MUTEX_NAME);
	BOOL   bResult = hMutex != NULL;

	if (bResult)
		CloseHandle(hMutex);

	return bResult;
}

BOOL SetUntrustedLabel()
{
	BYTE  sacl[1024];
	PACL  pSacl = (PACL)sacl;
	BYTE  sid[SECURITY_MAX_SID_SIZE];
	PSID  pSid = (PSID)sid;
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;

	InitializeAcl(pSacl, 1024, ACL_REVISION);
	CreateWellKnownSid(WinUntrustedLabelSid, NULL, pSid, &dwSidSize);
	AddMandatoryAce(pSacl, ACL_REVISION, 0, 0, pSid);

	return SetNamedSecurityInfo((LPWSTR)MUTEX_NAME, SE_KERNEL_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, pSacl) == ERROR_SUCCESS;
}