#include <windows.h>
#include <stdio.h>

BOOL CheckUserName(PTOKEN_USER pTokenUser);
BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName);

// トークンユーザーを表示

int main()
{
	DWORD       dwLength;
	HANDLE      hToken;
	PTOKEN_USER pTokenUser;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);

	int nExitCode = CheckUserName(pTokenUser) ? 0 : -1;

	LocalFree(pTokenUser);
	CloseHandle(hToken);

	return nExitCode;
}

BOOL CheckUserName(PTOKEN_USER pTokenUser)
{
	WCHAR szTokenUser[256];
	WCHAR szUserName[256];
	DWORD dwSize;

	ConvertSidToName(pTokenUser->User.Sid, szTokenUser, sizeof(szTokenUser) / sizeof(WCHAR));

	dwSize = sizeof(szUserName) / sizeof(WCHAR);
	GetUserName(szUserName, &dwSize);

	printf("%ws", szTokenUser);

	return lstrcmp(szTokenUser, szUserName) == 0;
}

BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName)
{
	WCHAR        szDomainName[256];
	DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	SID_NAME_USE sidName;

	return LookupAccountSid(NULL, pSid, lpszName, &dwSizeName, szDomainName, &dwSizeDomain, &sidName);
}