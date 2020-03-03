#include <windows.h>
#include <stdio.h>

// 現在ユーザーが対話型ログオンしたか確認

int main()
{
	BOOL  bResult;
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID  pSid = (PSID)LocalAlloc(LPTR, dwSidSize);

	CreateWellKnownSid(WinInteractiveSid, NULL, pSid, &dwSidSize);

	CheckTokenMembership(NULL, pSid, &bResult);
	if (bResult)
		printf("現在ユーザーは対話型ログオンした");
	else
		printf("現在ユーザーは対話型ログオンしていない");

	LocalFree(pSid);

	return 0;
}
