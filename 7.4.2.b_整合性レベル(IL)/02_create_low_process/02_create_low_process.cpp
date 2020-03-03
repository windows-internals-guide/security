#include <stdio.h>
#include <windows.h>

HANDLE RestartProcess(LPWSTR lpszKey);
HANDLE GetLowToken();
int CreateTestFile();

// 整合性レベル「低」のプロセスがカレントディレクトリにファイルを作成できないことを確認

int main()
{
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CreateTestFile();
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
		if (dwResult == -1) {
			printf("整合性レベル「低」なのでファイルを作成できない");
			nExitCode = 0;
		}
		else {
			printf("ファイルを作成できてしまった");
		}
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

HANDLE RestartProcess(LPWSTR lpszKey)
{
	HANDLE              hTokenLow;
	WCHAR               szModuleName[MAX_PATH];
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	hTokenLow = GetLowToken();
	if (hTokenLow == NULL)
		return NULL;

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
	if (CreateProcessWithTokenW(hTokenLow, 0, szModuleName, lpszKey, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}

	CloseHandle(hTokenLow);

	return processInformation.hProcess;
}

HANDLE GetLowToken()
{
	HANDLE                hTokenDuplicate;
	TOKEN_MANDATORY_LABEL mandatoryLabel;
	PSID                  pSid;
	DWORD                 dwSidSize;

	dwSidSize = SECURITY_MAX_SID_SIZE;
	pSid = (PSID)LocalAlloc(LPTR, dwSidSize);
	CreateWellKnownSid(WinLowLabelSid, NULL, pSid, &dwSidSize);

	mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
	mandatoryLabel.Label.Sid = pSid;

	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken);
	DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &hTokenDuplicate);

	if (!SetTokenInformation(hTokenDuplicate, TokenIntegrityLevel, &mandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pSid))) {
		CloseHandle(hTokenDuplicate);
		hTokenDuplicate = NULL;
	}

	LocalFree(pSid);

	return hTokenDuplicate;
}

int CreateTestFile()
{
	HANDLE hFile;

	hFile = CreateFile(L"test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	CloseHandle(hFile);

	return 0;
}
