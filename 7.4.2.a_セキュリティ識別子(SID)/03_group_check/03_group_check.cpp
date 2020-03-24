#include <windows.h>
#include <stdio.h>

BOOL IsGroupEnabled(WELL_KNOWN_SID_TYPE type);

// 匿名アカウントがEveryoneグループを含まない事を確認

int main()
{
	if (!IsGroupEnabled(WinWorldSid)) {
		printf("Everyoneが含まれていない");
		return -1;
	}
	
	ImpersonateAnonymousToken(GetCurrentThread());
	
	int nExitCode = -1;
	if (!IsGroupEnabled(WinWorldSid)) {
		printf("匿名アカウントはEveryoneを含まない");
		nExitCode = 0;
	}
	else {
		printf("匿名アカウントがEveryoneを含んでしまっている");
	}

	RevertToSelf();

	return nExitCode;
}

BOOL IsGroupEnabled(WELL_KNOWN_SID_TYPE type)
{
	BOOL  bResult;
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID  pSid = (PSID)LocalAlloc(LPTR, dwSidSize);

	CreateWellKnownSid(type, NULL, pSid, &dwSidSize);

	CheckTokenMembership(NULL, pSid, &bResult);

	LocalFree(pSid);

	return bResult;
}
