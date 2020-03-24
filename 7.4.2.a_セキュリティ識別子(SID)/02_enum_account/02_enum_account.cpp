#include <windows.h>
#include <lm.h>
#include <stdio.h>

#pragma comment (lib, "netapi32.lib")

BOOL ConvertNameToSid(LPWSTR lpszName, PSID *ppSid);
BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName);

// SIDベースでアカウントを列挙できることを確認

int main()
{
	DWORD i;
	DWORD dwSubAuthorityCount;
	DWORD dwBufferSize;
	WCHAR szAccountName[256];
	PSID  pSidUser;
	int   nAdministratorRid = -1;
	int   nGuestRid = -1;

	dwBufferSize = sizeof(szAccountName) / sizeof(WCHAR);
	GetUserName(szAccountName, &dwBufferSize);
	ConvertNameToSid(szAccountName, &pSidUser);

	dwSubAuthorityCount = *GetSidSubAuthorityCount(pSidUser);
	for (i = 500; i < 1500; i++) {
		*GetSidSubAuthority(pSidUser, dwSubAuthorityCount - 1) = i;
		ConvertSidToName(pSidUser, szAccountName, sizeof(szAccountName) / sizeof(WCHAR));
		if (lstrcmp(szAccountName, L"Administrator") == 0)
			nAdministratorRid = i;
		else if (lstrcmp(szAccountName, L"Guest") == 0) {
			nGuestRid = i;
		}

		szAccountName[0] = '\0';
	}

	LocalFree(pSidUser);

	int nExitCode = -1;
	if (nAdministratorRid == 500 && nGuestRid == 501) {
		printf("AdministratorとGuestを確認した");
		nExitCode = 0;
	}
	else
		printf("AdministratorかGuestを確認できなかった");

	return nExitCode;
}

BOOL ConvertNameToSid(LPWSTR lpszName, PSID *ppSid)
{
	WCHAR        szDomainName[256];
	DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	DWORD        dwSizeSid = 0;
	SID_NAME_USE sidName;

	LookupAccountName(NULL, lpszName, NULL, &dwSizeSid, szDomainName, &dwSizeDomain, &sidName);

	*ppSid = (PSID)LocalAlloc(LPTR, dwSizeSid);

	return LookupAccountName(NULL, lpszName, *ppSid, &dwSizeSid, szDomainName, &dwSizeDomain, &sidName);
}

BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName)
{
	WCHAR        szDomainName[256];
	DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	SID_NAME_USE sidName;

	return LookupAccountSid(NULL, pSid, lpszName, &dwSizeName, szDomainName, &dwSizeDomain, &sidName);
}
