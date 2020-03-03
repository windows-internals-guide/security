#include <stdio.h>
#include <windows.h>
#include <ntsecapi.h>

#pragma comment (lib, "secur32.lib")

PSECURITY_LOGON_SESSION_DATA GetLogonSessionData();

// 現在ユーザーのログオンにNTLMが使われたことを確認

int main()
{
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData = GetLogonSessionData();

	if (pLogonSessionData == NULL) {
		printf("ログオンセッションのデータを取得できません。");
		return -1;
	}

	int nExitCode = -1;

	if (lstrcmp(pLogonSessionData->AuthenticationPackage.Buffer, L"NTLM") == 0) {
		printf("ログオンにNTLMプロトコルが使用されている");
		nExitCode = 0;
	}
	else
		printf("ログオンにNTLMプロトコルが使用されていない");

	LsaFreeReturnBuffer(pLogonSessionData);

	return nExitCode;
}

PSECURITY_LOGON_SESSION_DATA GetLogonSessionData()
{
	DWORD                        dwLength;
	HANDLE                       hToken;
	PTOKEN_STATISTICS            pTokenStatistics;
	NTSTATUS                     ns;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwLength);
	pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength);

	ns = LsaGetLogonSessionData(&pTokenStatistics->AuthenticationId, &pLogonSessionData);

	LocalFree(pTokenStatistics);
	CloseHandle(hToken);

	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		return NULL;
	}

	return pLogonSessionData;
}