#include <stdio.h>
#include <windows.h>
#include <ntsecapi.h>

#pragma comment (lib, "secur32.lib")

#define FLAG_ELEVEATED 0x01
#define FLAG_FILTERD 0x02
#define FLAG_ALL 0x03

TOKEN_ELEVATION_TYPE GetElevationTypeFromLogonSessionId(PLUID pLuid);
BOOL EqualLuid(HANDLE hToken, PLUID pLuid);

// 同じユーザー名の2つのログオンセッションを確認

int main()
{
	ULONG                        i;
	ULONG                        uLogonSessionCount;
	NTSTATUS                     ns;
	PLUID                        pLogonSessionList = NULL;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData;
	TOKEN_ELEVATION_TYPE         type;
	WCHAR                        szUserName[MAX_PATH];
	DWORD                        dwBufferSize = sizeof(szUserName) / sizeof(WCHAR);
	DWORD                        dwFlag = 0;

	GetUserName(szUserName, &dwBufferSize);

	ns = LsaEnumerateLogonSessions(&uLogonSessionCount, &pLogonSessionList);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS && pLogonSessionList != NULL) {
		printf("ログオンセッションを列挙できない");
		return -1;
	}

	for (i = 0; i < uLogonSessionCount; i++) {
		ns = LsaGetLogonSessionData(&pLogonSessionList[i], &pLogonSessionData);
		if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS)
			continue;

		if (lstrcmp(pLogonSessionData->UserName.Buffer, szUserName) == 0) {
			type = GetElevationTypeFromLogonSessionId(&pLogonSessionList[i]);
			if (type == TokenElevationTypeFull)
				dwFlag |= FLAG_ELEVEATED;
			else if (type == TokenElevationTypeDefault)
				dwFlag |= FLAG_FILTERD;
		}

		LsaFreeReturnBuffer(pLogonSessionData);
	}

	LsaFreeReturnBuffer(pLogonSessionList);

	int nExitCode = -1;

	if (dwFlag & FLAG_ALL) {
		printf("昇格とフィルターどちらも確認");
		nExitCode = 0;
	}
	else if (dwFlag & FLAG_ELEVEATED) {
		printf("フィルターを確認できない");
	}
	else if (dwFlag & FLAG_FILTERD) {
		printf("昇格を確認できない");
	}
	else if (dwFlag == 0) {
		printf("昇格とフィルターどちらも確認できない");
	}

	return nExitCode;
}

TOKEN_ELEVATION_TYPE GetElevationTypeFromLogonSessionId(PLUID pLuid)
{
	HANDLE               hToken;
	DWORD                dwLength;
	TOKEN_LINKED_TOKEN   linkedToken;
	TOKEN_ELEVATION_TYPE type = TokenElevationTypeLimited;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	if (EqualLuid(hToken, pLuid)) {
		CloseHandle(hToken);
		return type;
	}

	GetTokenInformation(hToken, TokenLinkedToken, &linkedToken, sizeof(TOKEN_LINKED_TOKEN), &dwLength);
	if (EqualLuid(linkedToken.LinkedToken, pLuid)) {
		type = TokenElevationTypeFull;
	}
	else {
		type = TokenElevationTypeDefault;
	}

	CloseHandle(linkedToken.LinkedToken);
	CloseHandle(hToken);

	return type;
}

BOOL EqualLuid(HANDLE hToken, PLUID pLuid)
{
	BOOL              bResult;
	DWORD             dwLength;
	PTOKEN_STATISTICS pTokenStatistics;

	GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwLength);
	pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLength, &dwLength);

	bResult = pTokenStatistics->AuthenticationId.HighPart == pLuid->HighPart && pTokenStatistics->AuthenticationId.LowPart == pLuid->LowPart;

	LocalFree(pTokenStatistics);

	return bResult;
}