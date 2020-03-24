#include <stdio.h>
#include <windows.h>
#include <aclapi.h>

PSECURITY_DESCRIPTOR GetWindowStationSecurity(PACL* ppDacl);
BOOL CALLBACK EnumWindowStationProc(LPWSTR lpszWindowStation, LPARAM lParam);
BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName);
void GetLogonSidName(LPWSTR lpszLogonSidName);

// winsta0のセキュリティ記述子を確認

int main()
{
	WCHAR                szAccountName[256];
	DWORD                i;
	PACL                 pDacl;
	PSECURITY_DESCRIPTOR pSecurityDescriptor;
	PACCESS_ALLOWED_ACE  pAce;
	ACL_SIZE_INFORMATION aclInformation;
	WCHAR                szLogonSidName[256];
	
	pSecurityDescriptor = GetWindowStationSecurity(&pDacl);
	if (pSecurityDescriptor == NULL)
		return -1;

	GetLogonSidName(szLogonSidName);

	GetAclInformation(pDacl, &aclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

	int nExitCode = -1;

#if 1
	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		ConvertSidToName((PSID)& pAce->SidStart, szAccountName, sizeof(szAccountName) / sizeof(WCHAR));
		if (lstrcmp(szLogonSidName, szAccountName) == 0)
			break;
	}

	if (i != aclInformation.AceCount) {
		printf("WinSta0にログオンSIDを確認した。");
		nExitCode = 0;
	}
	else
		printf("WinSta0にログオンSIDを確認できない");
#else
	for (i = 0; i < aclInformation.AceCount; i++) {
		GetAce(pDacl, i, (LPVOID*)& pAce);
		ConvertSidToName((PSID)& pAce->SidStart, szAccountName, sizeof(szAccountName) / sizeof(WCHAR));
		printf("%ws %08x\n", szAccountName, pAce->Mask);
	}
	nExitCode = 0;
#endif
	
	LocalFree(pSecurityDescriptor);

	return nExitCode;
}

PSECURITY_DESCRIPTOR GetWindowStationSecurity(PACL* ppDacl)
{
	BOOL bResult = FALSE;

	EnumWindowStations(EnumWindowStationProc, (LPARAM)& bResult);
	if (!bResult) {
		printf("WinSta0を確認できない");
		return NULL;
	}

	HWINSTA hwinsta;

	hwinsta = OpenWindowStation(L"WinSta0", FALSE, READ_CONTROL);
	if (hwinsta == NULL) {
		printf("WinSta0のセキュリティを読み取れない");
		return NULL;
	}

	DWORD dwLength;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;

	GetUserObjectSecurity(hwinsta, &si, NULL, 0, &dwLength);
	pSecurityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwLength);
	GetUserObjectSecurity(hwinsta, &si, pSecurityDescriptor, dwLength, &dwLength);

	PACL pDacl;
	BOOL bDaclPresent, bDaciExist;
	GetSecurityDescriptorDacl(pSecurityDescriptor, &bDaclPresent, &pDacl, &bDaciExist);

	*ppDacl = pDacl;

	CloseWindowStation(hwinsta);

	return pSecurityDescriptor;
}

BOOL CALLBACK EnumWindowStationProc(LPWSTR lpszWindowStation, LPARAM lParam)
{
	if (lstrcmpi(lpszWindowStation, L"WinSta0") == 0) { // not lstrcmp
		LPBOOL lpb = (LPBOOL)lParam;
		*lpb = TRUE;
		return FALSE;
	}

	return TRUE;
}

BOOL ConvertSidToName(PSID pSid, LPWSTR lpszName, DWORD dwSizeName)
{
	WCHAR        szDomainName[256];
	DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	SID_NAME_USE sidName;

	return LookupAccountSid(NULL, pSid, lpszName, &dwSizeName, szDomainName, &dwSizeDomain, &sidName);
}

void GetLogonSidName(LPWSTR lpszLogonSidName)
{
	DWORD         dwLength;
	HANDLE        hToken;
	PTOKEN_GROUPS pTokenGroups;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenLogonSid, pTokenGroups, dwLength, &dwLength);

	CloseHandle(hToken);

	ConvertSidToName(pTokenGroups->Groups[0].Sid, lpszLogonSidName, 256);

	LocalFree(pTokenGroups);
}