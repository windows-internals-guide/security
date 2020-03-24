#include <stdio.h>
#include <windows.h>
#include <aclapi.h>

#define FLAG_DEFAULT_DESKTOP 0x01
#define FLAG_SWITCH_WINLOGON 0x02
#define FLAG_VISIBLE_WINLOGON 0x04

int Check_Thread();
int Test_Switch();
int Test_Desktop();
BOOL CALLBACK EnumDesktopProc(LPWSTR lpszDesktop, LPARAM lParam);

// デスクトップに対するアクセスを確認

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください");
		return -1;
	}

	DWORD dwFlags = 0;

	dwFlags |= Check_Thread();
	dwFlags |= Test_Switch();
	dwFlags |= Test_Desktop();

	int nExitCode = -1;

	if (dwFlags == (FLAG_DEFAULT_DESKTOP | FLAG_VISIBLE_WINLOGON)) {
		printf("Winlogonデスクトップへの切り替えができないことを確認");
		nExitCode = 0;
	}
	else
		printf("デスクトップの確認結果が正しくない");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

int Check_Thread()
{
	HDESK hdesk = GetThreadDesktop(GetCurrentThreadId());

	WCHAR szName[256];
	DWORD dwLength = sizeof(szName) / sizeof(szName[0]);
	GetUserObjectInformation(hdesk, UOI_NAME, szName, dwLength, &dwLength);

	return lstrcmpi(szName, L"Default") == 0 ? FLAG_DEFAULT_DESKTOP  : 0;
}

int Test_Switch()
{
	HDESK hdesk = OpenDesktop(L"Winlogon", 0, FALSE, DESKTOP_SWITCHDESKTOP);
	if (hdesk == NULL) {
		return 0;
	}

	CloseDesktop(hdesk);

	return FLAG_SWITCH_WINLOGON;
}

int Test_Desktop()
{
	HWINSTA hwinsta = OpenWindowStation(L"WinSta0", FALSE, WINSTA_ENUMDESKTOPS);
	if (hwinsta == NULL) {
		return 0;
	}

	BOOL bResult = FALSE;
	EnumDesktops(hwinsta, EnumDesktopProc, (LPARAM)& bResult);

	CloseWindowStation(hwinsta);

	return FLAG_VISIBLE_WINLOGON;
}

BOOL CALLBACK EnumDesktopProc(LPWSTR lpszDesktop, LPARAM lParam)
{
	if (lstrcmp(lpszDesktop, L"Winlogon") == 0) {
		LPBOOL lpb = (LPBOOL)lParam;
		*lpb = TRUE;
		return FALSE;
	}

	return TRUE;
}
