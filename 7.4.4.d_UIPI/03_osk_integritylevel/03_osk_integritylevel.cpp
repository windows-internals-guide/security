#include <stdio.h>
#include <windows.h>
#include <shlobj.h>

HANDLE StartProcess(LPWSTR lpszApplicationName);
HANDLE StartProcessForKernel(LPWSTR lpszApplicationName);
HANDLE StartProcessForShell(LPWSTR lpszApplicationName);
int ShowIntegrityLevel(HANDLE hToken);
BOOL IsUIAccess(HANDLE hToken);

// osk.exe(UIAccessが1のプロセス)の整合性レベルを確認

int main()
{
	HANDLE hTargetToken;
	HANDLE hProcess;
	WCHAR  szApplicationName[] = L"C:\\Windows\\system32\\osk.exe";

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("プロセスハンドル取得のため管理者として実行してください。");
		return -1;
	}

	PVOID pValue;
	Wow64DisableWow64FsRedirection(&pValue);
	if (1) {
		hProcess = StartProcess(szApplicationName);
	}
	Wow64RevertWow64FsRedirection(pValue);

	if (hProcess == NULL) {
		return -1;
	}
	
	OpenProcessToken(hProcess, TOKEN_QUERY, &hTargetToken);
	int nExitCode = ShowIntegrityLevel(hTargetToken);
	CloseHandle(hTargetToken);

	TerminateProcess(hProcess, 0);
	CloseHandle(hProcess);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

HANDLE StartProcess(LPWSTR lpszApplicationName)
{
	HANDLE hProcess = StartProcessForKernel(lpszApplicationName);

	if (hProcess == NULL) {
		hProcess = StartProcessForShell(lpszApplicationName);
	}

	return hProcess;
}

HANDLE StartProcessForKernel(LPWSTR lpszApplicationName)
{
	PROCESS_INFORMATION processInformation;
	STARTUPINFO         startupInfo;

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);

	if (!CreateProcess(lpszApplicationName, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &processInformation)) {
		// printf("CreateProcessでは作成できない %d\n", GetLastError()); // ERROR_ELEVATION_REQUIRED
		return FALSE;
	}

	CloseHandle(processInformation.hThread);

	return processInformation.hProcess;
}

HANDLE StartProcessForShell(LPWSTR lpszApplicationName)
{
	if (1) {
		HRESULT hr;

		CoInitialize(NULL);

		IShellDispatch2* pShellDispatch2;
		hr = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pShellDispatch2));
		if (FAILED(hr))
			return FALSE;

		VARIANT varOperation;
		varOperation.vt = VT_BSTR;
		varOperation.bstrVal = SysAllocString(L"open");

		VARIANT varShow;
		varShow.vt = VT_I4;
		varShow.lVal = 1;

		VARIANT vtEmpty = {};

		BSTR bstr = SysAllocString(lpszApplicationName);
		hr = pShellDispatch2->ShellExecuteW(bstr, vtEmpty, vtEmpty, varOperation, varShow);
		SysFreeString(bstr);

		VariantClear(&varOperation);

		CoUninitialize();
	}
	else {
		ShellExecute(0, L"open", lpszApplicationName, NULL, 0, SW_SHOW);
	}

	HWND hwnd;
	int i = 0;
	for (i = 0; i < 10; i++) {
		hwnd = FindWindow(L"OSKMainClass", NULL);
		if (hwnd != NULL)
			break;
		Sleep(100);
	}

	DWORD dwProcessId, dwThreadId;
	dwThreadId = GetWindowThreadProcessId(hwnd, &dwProcessId);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, dwProcessId);
	if (hProcess == NULL) {
		printf("osk.exeのプロセスのハンドルを取得できなかった %d\n", GetLastError());
		return NULL;
	}

	return hProcess;
}

int ShowIntegrityLevel(HANDLE hToken)
{
	WCHAR                  szName[256];
	WCHAR                  szDomainName[256];
	DWORD                  dwSizeName;
	DWORD                  dwSizeDomain;
	DWORD                  dwLength;
	SID_NAME_USE           sidName;
	PTOKEN_MANDATORY_LABEL pMandatoryLabel;

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
	pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
	if (pMandatoryLabel == NULL) {
		return -1;
	}
	GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, dwLength, &dwLength);

	dwSizeName = sizeof(szName) / sizeof(WCHAR);
	dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
	LookupAccountSid(NULL, pMandatoryLabel->Label.Sid, szName, &dwSizeName, szDomainName, &dwSizeDomain, &sidName);

	DWORD dwSubAuthorityCount = *GetSidSubAuthorityCount(pMandatoryLabel->Label.Sid);
	DWORD dwRid = *GetSidSubAuthority(pMandatoryLabel->Label.Sid, dwSubAuthorityCount - 1);

	int nExitCode = -1;
	if (dwRid >= SECURITY_MANDATORY_HIGH_RID) {
		if (IsUIAccess(hToken)) {
			printf("%04x %ws", dwRid, szName);
			nExitCode = 0;
		}
		else {
			printf("何故かUIAccessが1でない");
		}
	}
	else {
		printf("RIDがSECURITY_MANDATORY_HIGH_RIDより低い");
	}	

	LocalFree(pMandatoryLabel);

	return nExitCode;
}

BOOL IsUIAccess(HANDLE hToken)
{
	DWORD dwUIAccess;
	DWORD dwLength = sizeof(dwUIAccess);

	GetTokenInformation(hToken, TokenUIAccess, &dwUIAccess, sizeof(dwUIAccess), &dwLength);

	return dwUIAccess == 1;
}