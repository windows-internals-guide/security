#include <stdio.h>
#include <windows.h>
#include <ntsecapi.h>

HANDLE GetAdminToken();
BOOL IsElevated(HANDLE hAdminToken);
BOOL CheckImpersonation(HANDLE hAdminToken);

// 標準ユーザーのトークンに管理者トークンが関連付けられていることを確認

int main()
{
	HANDLE hAdminToken = GetAdminToken();
	if (hAdminToken == NULL) {
		printf("プロセスは既に昇格されている");
		return -1;
	}

	int nExitCode = -1;
	if (IsElevated(hAdminToken)) {
		if (!CheckImpersonation(hAdminToken)) {
			printf("リンクトークンは昇格されており、偽装もできない");
			nExitCode = 0;
		}
		else
			printf("リンクトークンで偽装できてしまった");
	}
	else
		printf("リンクトークンが昇格されていない");

	CloseHandle(hAdminToken);

	return nExitCode;
}

BOOL IsElevated(HANDLE hAdminToken)
{
	DWORD dwLength;
	TOKEN_ELEVATION tokenElevation;

	if (!GetTokenInformation(hAdminToken, TokenElevation, &tokenElevation, sizeof(TOKEN_ELEVATION), &dwLength)) {
		return FALSE;
	}

	return tokenElevation.TokenIsElevated;
}

BOOL CheckImpersonation(HANDLE hAdminToken)
{
	if (!ImpersonateLoggedOnUser(hAdminToken)) {
		return FALSE;
	}
	
	NTSTATUS              ns;
	LSA_HANDLE            hPolicy;
	LSA_OBJECT_ATTRIBUTES objectAttributes;

	ZeroMemory(&objectAttributes, sizeof(LSA_OBJECT_ATTRIBUTES));
	objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

	ns = LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_AUDIT_INFORMATION | POLICY_SET_AUDIT_REQUIREMENTS, &hPolicy);
	if (LsaNtStatusToWinError(ns) != ERROR_SUCCESS) {
		return FALSE;
	}

	LsaClose(hPolicy);
	
	return TRUE;
}

HANDLE GetAdminToken()
{
	HANDLE hToken;
	DWORD  dwLength;
	TOKEN_LINKED_TOKEN linkedToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	if (!GetTokenInformation(hToken, TokenLinkedToken, &linkedToken, sizeof(TOKEN_LINKED_TOKEN), &dwLength)) {
		CloseHandle(hToken);
		return NULL;
	}

	CloseHandle(hToken);

	return linkedToken.LinkedToken;
}