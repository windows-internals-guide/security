#include <windows.h>
#include <stdio.h>

int CheckLogonSid();
HANDLE RestartProcess(LPWSTR lpszUserName, LPWSTR lpszPassword, LPWSTR lpszKey);

// CreateProcessWithLogonWで作成したプロセスがデスクトップにアクセスできることを確認

int main()
{
	WCHAR szUserName[] = L"";
	WCHAR szPassword[] = L"";
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckLogonSid();
	}

	if (szUserName[0] == '\0' || szPassword[0] == '\0') {
		printf("ユーザー名またはパスワードが設定されていない");
		return -1;
	}

	int nExitCode = -1;
	HANDLE hRestartProcess = RestartProcess(szUserName, szPassword, szKey);
	if (hRestartProcess != NULL) {
		DWORD dwResult;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwResult);
		if (dwResult == 0) {
			printf("作成したプロセスのトークンは、デスクトップと同一のログオンSIDを持つ。");
			nExitCode = 0;
		}
		else
			printf("作成したプロセスのトークンは、デスクトップと同一のログオンSIDを持たない。");
		CloseHandle(hRestartProcess);
	}
	else
		printf("特定ユーザーとしてのプロセス作成に失敗した。 %d", GetLastError());

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

int CheckLogonSid()
{
	DWORD dwLength;
	PSID  pSid;
	GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_USER_SID, NULL, 0, &dwLength);
	pSid = (PSID)LocalAlloc(LPTR, dwLength);
	GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_USER_SID, pSid, dwLength, &dwLength);

	HANDLE hToken;
	PTOKEN_GROUPS pTokenGroups;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenLogonSid, pTokenGroups, dwLength, &dwLength);
	CloseHandle(hToken);

	BOOL bResult = EqualSid(pSid, pTokenGroups->Groups[0].Sid);

	LocalFree(pSid);
	LocalFree(pTokenGroups);

	return bResult ? 0 : -1;
}

HANDLE RestartProcess(LPWSTR lpszUserName, LPWSTR lpszPassword, LPWSTR lpszKey)
{
	WCHAR               szModuleName[MAX_PATH];
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = NULL;

	if (CreateProcessWithLogonW(lpszUserName, NULL, lpszPassword, 0, szModuleName, lpszKey, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}

	return processInformation.hProcess;
}
