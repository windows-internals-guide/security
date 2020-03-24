#include <stdio.h>
#include <windows.h>
#include <wincred.h>

#pragma comment (lib, "credui.lib")

BOOL CheckLogonAndImpersonation(LPWSTR lpszUserName, LPWSTR lpszPassword);
void SetLowToken();

// 整合レベルが「低」でもユーザーをログオンさせれるが、偽装しても偽装トークンが割り当てられないことを確認

int main()
{
#if 1
	WCHAR szUserName[] = L"";
	WCHAR szPassword[] = L"";

	// 通常はCredUIPromptForCredentialsで受け取るが、自動テストのため、事前に設定しておく
	if (szUserName[0] == '\0' || szPassword[0] == '\0') {
		printf("ユーザー名またはパスワードが設定されていない");
		return -1;
	}

#else
	WCHAR  szUserName[256] = { 0 };
	WCHAR  szPassword[256] = { 0 };
	DWORD  dwResult;

	dwResult = CredUIPromptForCredentials(NULL, L"my_credential", NULL, 0, szUserName, sizeof(szUserName) / sizeof(WCHAR),
		szPassword, sizeof(szPassword) / sizeof(WCHAR), &bSave, CREDUI_FLAGS_EXPECT_CONFIRMATION | CREDUI_FLAGS_GENERIC_CREDENTIALS);
	if (dwResult != NO_ERROR) {
		return -1;
	}
#endif

	int nExitCode = -1;
	if (CheckLogonAndImpersonation(szUserName, szPassword)) {
		printf("整合レベル「低」は整合レベル「中」のトークンを偽装できない");
		nExitCode = 0;
	}
	
	SecureZeroMemory(szPassword, sizeof(szPassword));

	return nExitCode;
}

BOOL CheckLogonAndImpersonation(LPWSTR lpszUserName, LPWSTR lpszPassword)
{
	HANDLE hToken;

	SetLowToken();

	if (!LogonUser(lpszUserName, NULL, lpszPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
		printf("ログオンに失敗した %d", GetLastError());
		return FALSE;
	}

	if (ImpersonateLoggedOnUser(hToken)) {
		HANDLE hTokenImpersonation;
		OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hTokenImpersonation);
		if (hTokenImpersonation == NULL) {
			// ERROR_BAD_IMPERSONATION_LEVEL
			RevertToSelf();
			CloseHandle(hToken);
			return TRUE;
		}

		printf("偽装トークンを取得できてしまった");
		RevertToSelf();
		CloseHandle(hTokenImpersonation);
	}
	else {
		printf("ImpersonateLoggedOnUserの呼び出しに失敗");
	}

	CloseHandle(hToken);

	return FALSE;
}

void SetLowToken()
{
	HANDLE hToken;
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