#include <strsafe.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ip2string.h>
#include <lm.h>

#pragma comment (lib, "netapi32.lib")
#pragma comment (lib, "iphlpapi.lib")
#pragma comment (lib, "ntdll.lib")

void ImpersonateFilterdAminToken();
void GetIpAddress(LPWSTR lpszIpAddress);

// IPアドレス指定のユーザー列挙は、標準ユーザーはできないことを確認

int main()
{
	DWORD        i, dwError;
	DWORD        dwEntryCount;
	DWORD        dwTotalEntries;
	PUSER_INFO_0 pUserInfo;
	WCHAR        szIpAddress[256];
	
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return -1;
	}
	
	GetIpAddress(szIpAddress);

	int nExitCode = -1;

	dwError = NetUserEnum(szIpAddress, 0, 0, (LPBYTE*)& pUserInfo, MAX_PREFERRED_LENGTH, &dwEntryCount, &dwTotalEntries, NULL);
	if (dwError == NERR_Success) {
		NetApiBufferFree(pUserInfo);

		ImpersonateFilterdAminToken();
		dwError = NetUserEnum(szIpAddress, 0, 0, (LPBYTE*)& pUserInfo, MAX_PREFERRED_LENGTH, &dwEntryCount, &dwTotalEntries, NULL);
		RevertToSelf();
		if (dwError != NERR_Success) {
			printf("標準ユーザーがユーザー列挙できないことを確認");
			nExitCode = 0;
		}
		else {
			for (i = 0; i < dwEntryCount; i++)
				printf("%ws\n", pUserInfo[i].usri0_name);
			NetApiBufferFree(pUserInfo);
		}
	}
	else
		printf("管理者なのにユーザー列挙できない");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

void ImpersonateFilterdAminToken()
{
	HANDLE             hTokenFull;
	TOKEN_LINKED_TOKEN linkedToken;
	DWORD              dwLength;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTokenFull);

	GetTokenInformation(hTokenFull, TokenLinkedToken, &linkedToken, sizeof(TOKEN_LINKED_TOKEN), &dwLength);
	ImpersonateLoggedOnUser(linkedToken.LinkedToken);

	CloseHandle(hTokenFull);
}

void GetIpAddress(LPWSTR lpszIpAddress)
{
	DWORD            i;
	DWORD            dwSize = 0;
	PMIB_IPADDRTABLE pIpAddrTable;
	WCHAR            szIpAddress[256] = L"";

	GetIpAddrTable(NULL, &dwSize, 0);
	pIpAddrTable = (PMIB_IPADDRTABLE)LocalAlloc(LPTR, dwSize);
	GetIpAddrTable(pIpAddrTable, &dwSize, 0);

	for (i = 0; i < pIpAddrTable->dwNumEntries; i++) {
		RtlIpv4AddressToString((const in_addr*)& pIpAddrTable->table[i].dwAddr, szIpAddress);
		if (lstrcmp(szIpAddress, L"127.0.0.1") != 0)
			break;
	}

	StringCchCopy(lpszIpAddress, ARRAYSIZE(szIpAddress), szIpAddress);

	LocalFree(pIpAddrTable);
}
