#include <windows.h>
#include <stdio.h>
#include <sddl.h>

BOOL CheckLogonSidAuthority(PSID pLogonSid);
BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName);

// トークングループにログオンSIDが含まれる事を確認

int main()
{
	DWORD         i;
	DWORD         dwLength;
	HANDLE        hToken;
	PTOKEN_GROUPS pTokenGroups;
	PSID          pLogonSid = NULL;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLength, &dwLength);

	for (i = 0; i < pTokenGroups->GroupCount; i++) {
		if (pTokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
			pLogonSid = pTokenGroups->Groups[i].Sid;
		}

#if 0
		LPWSTR lpszSid;
		WCHAR  szSidName[256];
		ConvertSidToStringSid(pTokenGroups->Groups[i].Sid, &lpszSid);
		ConvertSidToName(pTokenGroups->Groups[i].Sid, szSidName, sizeof(szSidName) / sizeof(WCHAR));
		printf("%ws(%ws)\n", szSidName, lpszSid);
		LocalFree(lpszSid);
#endif
	}

	int nExitCode = -1;

	if (pLogonSid != NULL) {
		if (CheckLogonSidAuthority(pLogonSid)) {
			printf("ログオンSIDは、S-1-5-5-X-Yの形式になっている。");
			nExitCode = 0;
		}
		else
			printf("ログオンSIDは、S-1-5-5-X-Yの形式になっていない。");
	}
	else
		printf("ログオンSIDを確認できない。");
	
	LocalFree(pTokenGroups);
	CloseHandle(hToken);

	return 0;
}

BOOL CheckLogonSidAuthority(PSID pLogonSid)
{
	PSID_IDENTIFIER_AUTHORITY pAuthority = GetSidIdentifierAuthority(pLogonSid);

	return pAuthority->Value[5] == 5 && *GetSidSubAuthority(pLogonSid, 0) == 5;
}

BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName)
{
	WCHAR        szDomainName[256];
	DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	SID_NAME_USE sidName;

	return LookupAccountSid(NULL, pSid, lpszName, &dwSizeName, szDomainName, &dwSizeDomain, &sidName);
}