#include <windows.h>
#include <aclapi.h>
#include <stdio.h>

PTOKEN_MANDATORY_LABEL GetProcessMandatoryLabel();
BOOL IsMediumSid(PSID pSid);
void PrintSid(PSID pSid);

// 現在プロセスの整合性レベルを確認

int main()
{
	PTOKEN_MANDATORY_LABEL pMandatoryLabel = GetProcessMandatoryLabel();

	if (pMandatoryLabel == NULL) {
		return 0;
	}
	
	int nExitCode = -1;
	if (IsMediumSid(pMandatoryLabel->Label.Sid)) {
		PrintSid(pMandatoryLabel->Label.Sid);
		nExitCode = 0;
	}
	else
		printf("SIDの整合性レベルが「中」でない");

	LocalFree(pMandatoryLabel);

	return nExitCode;
}

PTOKEN_MANDATORY_LABEL GetProcessMandatoryLabel()
{
	HANDLE                 hToken;
	DWORD                  dwLength;
	PTOKEN_MANDATORY_LABEL pMandatoryLabel;
	
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
	pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, dwLength, &dwLength);

	CloseHandle(hToken);

	return pMandatoryLabel;
}

BOOL IsMediumSid(PSID pSid)
{
	BYTE  sid[SECURITY_MAX_SID_SIZE];
	PSID  pMediumSid = (PSID)sid;
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	
	CreateWellKnownSid(WinMediumLabelSid, NULL, pMediumSid, &dwSidSize);
	
	return EqualSid(pSid, pMediumSid);
}

void PrintSid(PSID pSid)
{
	WCHAR        szName[256];
	WCHAR        szDomainName[256];
	DWORD        dwSizeName;
	DWORD        dwSizeDomain;
	SID_NAME_USE sidName;

	dwSizeName = sizeof(szName) / sizeof(WCHAR);
	dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	LookupAccountSid(NULL, pSid, szName, &dwSizeName, szDomainName, &dwSizeDomain, &sidName);

	printf("%ws", szName);
}
