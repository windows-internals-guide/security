#include <windows.h>
#include <stdio.h>

int CheckToken();
HANDLE RestartProcess(LPWSTR lpszKey);
HANDLE GetNormalUserToken();

// 昇格しているプロセスから標準ユーザーのプロセスを作成できることを確認

int main()
{
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckToken();
	}

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("プロセス作成のため管理者として実行してください。");
		return -1;
	}

	int nExitCode = -1;
	HANDLE hRestartProcess = RestartProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwResult;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwResult);
		if (dwResult == 0) {
			printf("標準ユーザーとしてのプロセス作成に成功。");
			nExitCode = 0;
		}
		else
			printf("標準ユーザーとしてのプロセス作成に失敗。");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセス作成に失敗。");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

int CheckToken()
{
	HANDLE hToken;
	HANDLE hTokenShell = GetNormalUserToken();

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	BOOLEAN bEqual = FALSE;
	typedef NTSTATUS(NTAPI * LPFNNTCOMPARETOKENS)(HANDLE, HANDLE, PBOOLEAN);
	HINSTANCE hmod = GetModuleHandle(L"ntdll.dll");
	if (hmod != NULL) {
		LPFNNTCOMPARETOKENS lpfnNtCompareTokens = (LPFNNTCOMPARETOKENS)GetProcAddress(hmod, "NtCompareTokens");
		if (lpfnNtCompareTokens != NULL) {
			lpfnNtCompareTokens(hToken, hTokenShell, &bEqual);
		}
	}

	CloseHandle(hToken);
	CloseHandle(hTokenShell);

	return bEqual ? 0 : -1;
}

HANDLE RestartProcess(LPWSTR lpszKey)
{
	HANDLE              hTokenMedium;
	WCHAR               szModuleName[MAX_PATH];
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	hTokenMedium = GetNormalUserToken();

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
	if (CreateProcessWithTokenW(hTokenMedium, 0, szModuleName, lpszKey, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}

	CloseHandle(hTokenMedium);

	return processInformation.hProcess;
}

HANDLE GetNormalUserToken()
{
	DWORD  dwProcessId;
	HANDLE hProcess;
	HANDLE hTokenNormal, hTokenDuplicate;

	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);
	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwProcessId);
	if (hProcess == NULL)
		return NULL;

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hTokenNormal)) {
		CloseHandle(hProcess);
		return NULL;
	}

	DuplicateTokenEx(hTokenNormal, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &hTokenDuplicate);

	CloseHandle(hProcess);
	CloseHandle(hTokenNormal);

	return hTokenDuplicate;
}