#include <windows.h>
#include <aclapi.h>
#include <strsafe.h>

// 必須整合性チェックを無効にできるか確認

int main()
{
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("管理者として実行してください。");
		return -1;
	}
	
	HANDLE hToken;

	OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);

	TOKEN_MANDATORY_POLICY policy;
	policy.Policy = TOKEN_MANDATORY_POLICY_OFF;
	SetTokenInformation(hToken, TokenMandatoryPolicy, &policy, sizeof(TOKEN_MANDATORY_POLICY));

	int nExitCode = -1;
	if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD) {
		printf("SE_TCB_NANE特権が有効でないため、必須整合性チェックを無効にできない。");
		nExitCode = 0;
	}
	else
		printf("必須整合性チェックを無効にできてしまった。");
		
	CloseHandle(hToken);
	
	return nExitCode;
}