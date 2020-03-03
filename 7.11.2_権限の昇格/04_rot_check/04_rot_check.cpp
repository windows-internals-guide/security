#include <stdio.h>
#include <windows.h>

HANDLE GetProcessHandleFromWindowClass(LPCWSTR lpszClassName);
HANDLE RestartProcess(LPWSTR lpszKey);
HANDLE GetNormalUserToken();
int CheckROT(LPWSTR lpszFilePath);
BOOL GetObjectFromROT(LPOLESTR lpszName, IUnknown** ppUnknown);

// 管理者プロセスがROTに登録したオブジェクトは、標準ユーザーが取得できないことを確認

int main()
{
	WCHAR szKey[] = L"restart-key";
	WCHAR szFilePath[] = L"C:\\Windows\\win.ini";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckROT(szFilePath);
	}

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("プロセスハンドル取得のため管理者として実行してください。");
		return -1;
	}

	ShellExecute(NULL, L"open", L"winword", szFilePath, NULL, SW_SHOWNORMAL);

	HANDLE hOfficeWordProcess = GetProcessHandleFromWindowClass(L"OpusApp");
	if (hOfficeWordProcess == NULL) {
		printf("プロセスのハンドルを取得できなかった %d", GetLastError());
		return -1;
	}

	// すぐにモニカが登録されるわけではないため待機
	Sleep(3000);

	if (CheckROT(szFilePath) == -1) {
		printf("管理者にもかかわらずROTから取得できない。");
		return -1;
	}

	int nExitCode = -1;
	HANDLE hRestartProcess = RestartProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwResult;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwResult);
		if (dwResult == -1) {
			printf("標準ユーザーなのでROTから取得できない");
			nExitCode = 0;
		}
		else
			printf("標準ユーザーなのにROTから取得できてしまった");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗した");

	TerminateProcess(hOfficeWordProcess, 0);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

HANDLE GetProcessHandleFromWindowClass(LPCWSTR lpszClassName)
{
	HWND hwnd;
	int i = 0;
	for (i = 0; i < 10; i++) {
		hwnd = FindWindow(lpszClassName, NULL);
		if (hwnd != NULL)
			break;
		Sleep(100);
	}

	DWORD dwProcessId, dwThreadId;
	dwThreadId = GetWindowThreadProcessId(hwnd, &dwProcessId);

	return OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, dwProcessId);
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

int CheckROT(LPWSTR lpszFilePath)
{
	int      nRetCode = -1;
	IUnknown* pUnknown;

	CoInitialize(NULL);

	GetObjectFromROT(lpszFilePath, &pUnknown);
	if (pUnknown != NULL) {
		nRetCode = 0;
		pUnknown->Release();
	}

	CoUninitialize();

	return nRetCode;
}

BOOL GetObjectFromROT(LPOLESTR lpszName, IUnknown** ppUnknown)
{
	HRESULT              hr;
	IMoniker* pMoniker;
	IEnumMoniker* pEnumMoniker;
	IBindCtx* pBindCtx;
	IRunningObjectTable* pRunningObjectTable;
	LPOLESTR             lpszDisplayName;

	*ppUnknown = NULL;

	GetRunningObjectTable(0, &pRunningObjectTable);
	pRunningObjectTable->EnumRunning(&pEnumMoniker);

	CreateBindCtx(NULL, &pBindCtx);

	while (pEnumMoniker->Next(1, &pMoniker, NULL) == S_OK) {
		pMoniker->GetDisplayName(pBindCtx, NULL, &lpszDisplayName);
		if (lstrcmpW(lpszName, lpszDisplayName) == 0) {
			hr = pRunningObjectTable->GetObject(pMoniker, ppUnknown);
			pMoniker->Release();
			break;
		}
		pMoniker->Release();
	}

	pBindCtx->Release();
	pEnumMoniker->Release();
	pRunningObjectTable->Release();

	return hr == S_OK;
}

/*
HRESULT Invoke(IDispatch *pDispatch, LPOLESTR lpszName, WORD wFlags, VARIANT *pVarArray, int nArgs, VARIANT *pVarResult)
{
	DISPPARAMS dispParams;
	DISPID     dispid;
	DISPID     dispidName = DISPID_PROPERTYPUT;
	HRESULT    hr;

	hr = pDispatch->GetIDsOfNames(IID_NULL, &lpszName, 1, LOCALE_USER_DEFAULT, &dispid);
	if (FAILED(hr))
		return hr;

	dispParams.cArgs = nArgs;
	dispParams.rgvarg = pVarArray;
	if (wFlags & DISPATCH_PROPERTYPUT) {
		dispParams.cNamedArgs = 1;
		dispParams.rgdispidNamedArgs = &dispidName;
	}
	else {
		dispParams.cNamedArgs = 0;
		dispParams.rgdispidNamedArgs = NULL;
	}

	hr = pDispatch->Invoke(dispid, IID_NULL, LOCALE_SYSTEM_DEFAULT, wFlags, &dispParams, pVarResult, NULL, NULL);

	return hr;
}

BOOL CreaeWordFile(LPOLESTR lpszFilePath)
{
	CLSID      clsid;
	HRESULT    hr;
	IDispatch  *pDispatch;
	VARIANT    var, varResult;
	IOleObject *pOleObject;

	hr = CLSIDFromProgID(L"Word.Document", &clsid); // Word.Application
	if (FAILED(hr)) {
		return FALSE;
	}

	hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pDispatch));
	if (FAILED(hr)) {
		return FALSE;
	}

	var.vt = VT_BSTR;
	var.bstrVal = SysAllocString(lpszFilePath);
	VariantInit(&varResult);
	Invoke(pDispatch, (LPOLESTR)L"SaveAs2", DISPATCH_METHOD, &var, 1, &varResult);

	pDispatch->QueryInterface(IID_PPV_ARGS(&pOleObject));
	pOleObject->Close(OLECLOSE_NOSAVE);
	pOleObject->Release();

	pDispatch->Release();

	return varResult.boolVal == VARIANT_TRUE;
}
*/