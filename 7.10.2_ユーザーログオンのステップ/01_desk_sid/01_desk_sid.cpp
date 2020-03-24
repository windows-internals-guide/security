#include <stdio.h>
#include <windows.h>
#include <aclapi.h>

PTOKEN_GROUPS GetLogonSid();
PSID GetUserObjectSid();

// デスクトップに割り当てられたSIDとトークンのログオンSIDを確認

int main()
{
	PTOKEN_GROUPS pTokenGroups = GetLogonSid();
	PSID          pSid = GetUserObjectSid();

	int nExitCode = -1;

	if (EqualSid(pTokenGroups->Groups[0].Sid, pSid)) {
		printf("トークンユーザーのログオンSIDとデスクトップのSIDは同一");
		nExitCode = 0;
	}
	else
		printf("トークンユーザーのログオンSIDとデスクトップのSIDは同一でない");

	LocalFree(pTokenGroups);
	LocalFree(pSid);

	return nExitCode;
}

PSID GetUserObjectSid()
{
	DWORD dwLength;
	PSID  pSid;

	GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_USER_SID, NULL, 0, &dwLength);
	pSid = (PSID)LocalAlloc(LPTR, dwLength);
	GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_USER_SID, pSid, dwLength, &dwLength);

	return pSid;
}

PTOKEN_GROUPS GetLogonSid()
{
	DWORD         dwLength;
	HANDLE        hToken;
	PTOKEN_GROUPS pTokenGroups;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenLogonSid, pTokenGroups, dwLength, &dwLength);

	CloseHandle(hToken);

	return pTokenGroups;
}