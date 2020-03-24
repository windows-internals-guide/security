#include <windows.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <userenv.h>

#pragma comment (lib, "userenv.lib")

HANDLE OpenSystemProcess();
HANDLE OpenSystemProcessToken(HANDLE hProcessSystem);
HANDLE RestartProcess(LPWSTR lpszKey, HANDLE hTokenSystem);
HANDLE RunAsSystem(LPWSTR lpszKey, HANDLE hTokenSystem, LPWSTR lpszApplicationName);
int CheckSystemAccount();
BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled);

int main()
{
	WCHAR szKey[] = L"restart-key";
	HANDLE hProcessSystem, hTokenSystem;

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckSystemAccount();
	}
	
	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("特権有効のため管理者として実行してください。");
		return -1;
	}

	if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
		printf("SE_DEBUG_NAME特権の有効に失敗。");
		return -1;
	}

	hProcessSystem = OpenSystemProcess();
	if (hProcessSystem == NULL) {
		printf("システムプロセスのハンドルの取得に失敗。");
		return 0;
	}

	hTokenSystem = OpenSystemProcessToken(hProcessSystem);
	if (hTokenSystem == NULL) {
		printf("システムプロセスのトークンの取得に失敗。");
		CloseHandle(hProcessSystem);
		return 0;
	}

	int nExitCode = -1;
	HANDLE hRestartProcess = RestartProcess(szKey, hTokenSystem);
	if (hRestartProcess != NULL) {
		DWORD dwResult;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwResult);
		if (dwResult == 0) {
			printf("SYSTEMとして昇格している。");
			nExitCode = 0;
		}
		else
			printf("SYSTEMとして昇格してない。");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗。");

	CloseHandle(hTokenSystem);
	CloseHandle(hProcessSystem);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

HANDLE OpenSystemProcess()
{
	HANDLE         hSnapshot;
	DWORD          dwProcessId;
	PROCESSENTRY32 pe;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	dwProcessId = 0;
	do {
		if (lstrcmp(pe.szExeFile, L"lsass.exe") == 0) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
}

HANDLE OpenSystemProcessToken(HANDLE hProcessSystem)
{
	HANDLE hToken, hTokenSystem;

	if (!OpenProcessToken(hProcessSystem, TOKEN_DUPLICATE, &hToken))
		return FALSE;

	DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, 0, SecurityIdentification, TokenPrimary, &hTokenSystem);

	CloseHandle(hToken);

	return hTokenSystem;
}

HANDLE RestartProcess(LPWSTR lpszKey, HANDLE hTokenSystem)
{
	DWORD dwSessionId;

	if (!EnablePrivilege(SE_TCB_NAME, TRUE)) {
		printf("SE_TCB_NAME特権の有効に失敗。");
		return NULL;
	}

	ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);

	if (!SetTokenInformation(hTokenSystem, TokenSessionId, &dwSessionId, sizeof(DWORD))) {
		printf("セッションIDの変更に失敗。");
		return NULL;
	}

	WCHAR szModuleName[MAX_PATH];
	GetModuleFileName(NULL, szModuleName, MAX_PATH);
	HANDLE hProcess = RunAsSystem(lpszKey, hTokenSystem, szModuleName);
	if (hProcess == NULL) {
		printf("プロセスの作成に失敗 %d。", GetLastError());
		return NULL;
	}

	return hProcess;
}

HANDLE RunAsSystem(LPWSTR lpszKey, HANDLE hTokenSystem, LPWSTR lpszApplicationName)
{
	LPVOID              lpEnvironment;
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";

	CreateEnvironmentBlock(&lpEnvironment, hTokenSystem, TRUE);

	if (CreateProcessAsUser(hTokenSystem, lpszApplicationName, lpszKey, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, lpEnvironment, NULL, &startupInfo, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}
	
	DestroyEnvironmentBlock(lpEnvironment);
	
	return processInformation.hProcess;
}

int CheckSystemAccount()
{
	DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
	PSID  pSid = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinLocalSystemSid, NULL, pSid, &dwSidSize);

	DWORD       dwLength;
	HANDLE      hToken;
	PTOKEN_USER pTokenUser;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);

	int nExitCode = EqualSid(pSid, pTokenUser->User.Sid) ? 0 : -1;

	LocalFree(pSid);
	CloseHandle(hToken);

	return nExitCode;
}

BOOL EnablePrivilege(LPCWSTR lpszPrivilege, BOOL bEnabled)
{
	BOOL             bResult;
	LUID             luid;
	HANDLE           hToken;
	TOKEN_PRIVILEGES tokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = bEnabled ? SE_PRIVILEGE_ENABLED : 0;

	bResult = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	CloseHandle(hToken);

	return bResult && GetLastError() == ERROR_SUCCESS;
}