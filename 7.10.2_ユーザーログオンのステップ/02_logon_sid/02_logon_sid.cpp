#include <stdio.h>
#include <windows.h>
#include <aclapi.h>

#define ACCESS_ATOM 0x01
#define ACCESS_CLIPBOARD 0x02
#define ACCESS_ENUMWINSTA 0x04

DWORD GetAccessFlags();
BOOL CALLBACK EnumWindowStationProc(LPWSTR lpszWindowStation, LPARAM lParam);
PTOKEN_GROUPS GetLogonSid(HANDLE hToken);
PSID GetUserObjectSid();

// 新しくログオンしたユーザーのログオンSIDは、デスクトップのSIDと異なる事を確認

int main()
{
	WCHAR  szUserName[] = L"";
	WCHAR  szPassword[] = L"";
	HANDLE hToken;
	
	if (szUserName[0] == '\0' || szPassword[0] == '\0') {
		printf("ユーザー名またはパスワードが設定されていない");
		return -1;
	}

	if (!LogonUser(szUserName, NULL, szPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
		if (GetLastError() == ERROR_LOGON_FAILURE)
			printf("ユーザー名またはパスワードが正しくありません。");
		else if (GetLastError() == ERROR_LOGON_TYPE_NOT_GRANTED)
			printf("必要なユーザー権利が割り当てられていません。");
		else
			printf("ログオンに失敗しました。 %d", GetLastError());
		return -1;
	}

	PTOKEN_GROUPS pTokenGroups = GetLogonSid(hToken);
	PSID          pSid = GetUserObjectSid();

	int nExitCode = -1;

	if (!EqualSid(pTokenGroups->Groups[0].Sid, pSid)) {
		DWORD dwFlags = 0;

		if (ImpersonateLoggedOnUser(hToken)) {
			dwFlags = GetAccessFlags();
			RevertToSelf();
		}

		if (dwFlags == (ACCESS_ATOM | ACCESS_CLIPBOARD)) {
			printf("ログオンSIDがデスクトップのSIDと異なるため、ウインドウステーションを列挙できない。");
			nExitCode = 0;
		}
		else
			printf("ログオンSIDはデスクトップのSIDと異なるが、アクセス結果が想定外。");
	}
	else
		printf("新しくログオンしたユーザーのログオンSIDがデスクトップのSIDと一致してしまった。");

	LocalFree(pTokenGroups);
	LocalFree(pSid);
	CloseHandle(hToken);

	return nExitCode;
}

DWORD GetAccessFlags()
{
	DWORD dwFlags = 0;

	ATOM atom = GlobalAddAtom(L"my_atom");
	if (atom != 0) {
		GlobalDeleteAtom(atom);
		dwFlags |= ACCESS_ATOM;
	}

	if (OpenClipboard(NULL)) {
		CloseClipboard();
		dwFlags |= ACCESS_CLIPBOARD;
	}

	if (EnumWindowStations(EnumWindowStationProc, 0)) {
		dwFlags |= ACCESS_ENUMWINSTA;
	}

#if 0
	HDESK hdesk = CreateDesktop(L"my_desk", NULL, NULL, 0, GENERIC_ALL, NULL);
	if (hdesk != NULL) {
		CloseDesktop(hdesk);
		dwFlags |= ACCESS_DESK;
	}
#endif

#if 0
	HDC hdc = GetDC(NULL);
	if (hdc != NULL) {
		RECT rc;
		GetClientRect(GetDesktopWindow(), &rc);
		Rectangle(hdc, rc.left, rc.top, rc.right / 2, rc.bottom / 2);
		ReleaseDC(NULL, hdc);
	}
#endif

	return dwFlags;
}

BOOL CALLBACK EnumWindowStationProc(LPWSTR lpszWindowStation, LPARAM lParam)
{
	return TRUE;
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

PTOKEN_GROUPS GetLogonSid(HANDLE hToken)
{
	DWORD         dwLength;
	PTOKEN_GROUPS pTokenGroups;

	GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenLogonSid, pTokenGroups, dwLength, &dwLength);

	return pTokenGroups;
}