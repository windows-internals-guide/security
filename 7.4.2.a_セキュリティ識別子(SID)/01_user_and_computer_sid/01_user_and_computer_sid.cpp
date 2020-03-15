#include <windows.h>
#include <lm.h>
#include <stdio.h>
#include <sddl.h>

#pragma comment (lib, "netapi32.lib")

BOOL EqualSubAuthority(PSID pSidComputer, PSID pSidUser);
PSID GetComputerSid();
PSID GetUserSid();

// ユーザーのSIDのRID以外がコンピュータSIDと同一な事を確認

int main()
{
	PSID pSidComputer = GetComputerSid();
	PSID pSidUser = GetUserSid();

	int nExitCode = -1;

	if (EqualSubAuthority(pSidComputer, pSidUser)) {
		printf("ユーザーのSIDはコンピュータSIDを内包している");
#if 0
		LPWSTR lpszComputerSid, lpszUserSid;
		ConvertSidToStringSid(pSidComputer, &lpszComputerSid);
		ConvertSidToStringSid(pSidUser, &lpszUserSid);
		printf("%ws\n", lpszComputerSid);
		printf("%ws\n", lpszUserSid);
		LocalFree(lpszComputerSid);
		LocalFree(lpszUserSid);
#endif
		nExitCode = 0;
	}
	else {
		printf("RID以外の一致を確認できない");
	}

	LocalFree(pSidComputer);
	LocalFree(pSidUser);

	return nExitCode;
}

BOOL EqualSubAuthority(PSID pSidComputer, PSID pSidUser)
{
	DWORD i, dw1, dw2;
	DWORD dwSubAuthorityCount = *GetSidSubAuthorityCount(pSidUser) - 1;

	for (i = 0; i < dwSubAuthorityCount; i++) {
		dw1 = *GetSidSubAuthority(pSidComputer, i);
		dw2 = *GetSidSubAuthority(pSidUser, i);
		if (dw1 != dw2)
			return FALSE;
	}

	return TRUE;
}

PSID GetComputerSid()
{
	WCHAR  szComputerName[256];
	DWORD  dwBufferSize;

	dwBufferSize = sizeof(szComputerName) / sizeof(WCHAR);
	GetComputerName(szComputerName, &dwBufferSize);

	PSID         pSidComputer;
	WCHAR        szDomainName[256];
	DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	DWORD        dwSizeSid = 0;
	SID_NAME_USE sidName;

	LookupAccountName(NULL, szComputerName, NULL, &dwSizeSid, szDomainName, &dwSizeDomain, &sidName);
	pSidComputer = (PSID)LocalAlloc(LPTR, dwSizeSid);
	LookupAccountName(NULL, szComputerName, pSidComputer, &dwSizeSid, szDomainName, &dwSizeDomain, &sidName);

	return pSidComputer;
}

PSID GetUserSid()
{
	DWORD dwSize;
	WCHAR szAccountName[256];
	
	dwSize = sizeof(szAccountName) / sizeof(WCHAR);
	GetUserName(szAccountName, &dwSize);

	PUSER_INFO_4 pUserInfo;
	if (NetUserGetInfo(NULL, szAccountName, 4, (LPBYTE *)&pUserInfo) != NERR_Success)
		return NULL;
	
	dwSize = GetLengthSid(pUserInfo->usri4_user_sid);
	PSID pSid = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
	CopySid(dwSize, pSid, pUserInfo->usri4_user_sid);

	NetApiBufferFree(pUserInfo);

	return pSid;
}
