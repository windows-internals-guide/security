#include <stdio.h>
#include <windows.h>
#include <wincred.h>

#pragma comment (lib, "credui.lib")

BOOL SaveCredential(LPWSTR szCredentialName);
BOOL IsCredential(LPWSTR lpszCredentialName);
void SetLowToken();
LRESULT CALLBACK CBTProc(int code, WPARAM wParam, LPARAM lParam);

// 認証ダイアログで保存されたクレデンシャルは、整合レベル「低」からでも列挙できることを確認

int main()
{
	WCHAR szCredentialName[] = L"my_credential";

	if (!SaveCredential(szCredentialName)) {
		printf("クレデンシャルの保存を確認できない");
		return -1;
	}

	int nExitCode = -1;
	if (IsCredential(szCredentialName)) {
		SetLowToken();
		CredDelete(szCredentialName, CRED_TYPE_GENERIC, 0);
		if (!IsCredential(szCredentialName)) {
			printf("整合レベル「低」でもクレデンシャルの削除を確認");
			nExitCode = 0;
		}
		else
			printf("クレデンシャルを削除できていない");
	}
	else
		printf("クレデンシャルを列挙できていない");

	return nExitCode;
}

BOOL SaveCredential(LPWSTR szCredentialName)
{
	WCHAR  szUserName[] = L"username";
	WCHAR  szPassword[] = L"password";
	DWORD  dwResult;
	BOOL   bSave = FALSE;

	HHOOK hhk = SetWindowsHookEx(WH_CBT, CBTProc, NULL, GetCurrentThreadId());

	// CREDUI_FLAGS_PERSISTを指定して、無条件に資格情報を保存
	// ※ダイアログを表示しない方法はない。
	dwResult = CredUIPromptForCredentials(NULL, szCredentialName, NULL, 0, szUserName, sizeof(szUserName) / sizeof(WCHAR),
		szPassword, sizeof(szPassword) / sizeof(WCHAR), &bSave, CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_PERSIST);
	
	UnhookWindowsHookEx(hhk);
	
	if (dwResult != NO_ERROR || !bSave) {	
		return FALSE;
	}

	return TRUE;
}

BOOL IsCredential(LPWSTR lpszCredentialName)
{
	DWORD        i, dwCount;
	PCREDENTIAL* pCredential = NULL;

	CredEnumerate(NULL, 0, &dwCount, &pCredential);
	for (i = 0; i < dwCount; i++) {
		if (lstrcmp(lpszCredentialName, pCredential[i]->TargetName) == 0) {
			break;
		}
	}

	if (pCredential != NULL)
		CredFree(pCredential);

	return i != dwCount;
}

void SetLowToken()
{
	HANDLE                hToken;
	DWORD                 dwSidSize;
	TOKEN_MANDATORY_LABEL mandatoryLabel;
	PSID                  pSidLow;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hToken)) {
		return;
	}

	dwSidSize = SECURITY_MAX_SID_SIZE;
	pSidLow = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinLowLabelSid, NULL, pSidLow, &dwSidSize);

	mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
	mandatoryLabel.Label.Sid = pSidLow;
	SetTokenInformation(hToken, TokenIntegrityLevel, &mandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pSidLow));

	LocalFree(pSidLow);
	CloseHandle(hToken);
}

LRESULT CALLBACK CBTProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code < 0)
		return CallNextHookEx(NULL, code, wParam, lParam);

	if (code == HCBT_ACTIVATE) {
		HWND hwnd = (HWND)wParam;
		PostMessage(hwnd, WM_COMMAND, IDOK, 0);
	}

	return CallNextHookEx(NULL, code, wParam, lParam);
}