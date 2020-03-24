#include <stdio.h>
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <strsafe.h>
#include <oleacc.h>
#include <uiautomationclient.h>

#pragma comment(lib, "oleacc.lib")
#pragma comment(lib, "wbemuuid.lib")

#define FLAG_GETTEXT 0x01
#define FLAG_SETTEXT 0x02
#define FLAG_APP 0x04
#define FLAG_COPYDATA 0x08
#define FLAG_WINEVENT 0x10
#define FLAG_ACCESSIBLE 0x20
#define FLAG_UIAUTOMATION 0x40
#define FLAG_BEST (FLAG_GETTEXT | FLAG_WINEVENT | FLAG_ACCESSIBLE | FLAG_UIAUTOMATION)

int GetText(HWND hwnd);
int SetText(HWND hwnd);
int SendApp(HWND hwnd);
int SendCopyData(HWND hwnd);
HWINEVENTHOOK Start_SetWinEventHook(DWORD dwProcessId, DWORD dwThreadId);
int CheckAccessibleObject(HWND hwnd);
int CheckUIAutomationElement(HWND hwnd);

HWND GenProcess();
BOOL ShellExecuteForShellDispatch(LPWSTR lpszPath);
int DeleteProcess(DWORD dwProcessId);

// osk.exe(UIAccessが1のプロセス)に対して、標準ユーザーから何が成功するか確認

int main()
{
	DWORD         dwProcessId, dwThreadId;
	HWINEVENTHOOK hWinEventHook;

	HWND  hwnd = GenProcess();
	if (hwnd == NULL) {
		printf("osk.exeのウインドウが見つからない\n");
		return 0;
	}

	dwThreadId = GetWindowThreadProcessId(hwnd, &dwProcessId);
	
	int nFlags = 0;

	nFlags |= GetText(hwnd);
	nFlags |= SetText(hwnd);
	nFlags |= SendApp(hwnd);
	nFlags |= SendCopyData(hwnd);

	hWinEventHook = Start_SetWinEventHook(dwProcessId, dwThreadId);
	if (hWinEventHook != NULL)
		nFlags |= FLAG_WINEVENT;

	nFlags |= CheckAccessibleObject(hwnd);
	nFlags |= CheckUIAutomationElement(hwnd);

	UnhookWinEvent(hWinEventHook);

	DeleteProcess(dwProcessId);

	int nExitCode = -1;
	if (nFlags == FLAG_BEST) {
		printf("アクセスは正しい");
		nExitCode = 0;
	}
	else
		printf("想定していないアクセス結果");

	return nExitCode;
}

int GetText(HWND hwnd)
{
	int   nFlags = 0;
	WCHAR szBuf[256];
	BOOL  bResult = SendMessage(hwnd, WM_GETTEXT, 256, (LPARAM)szBuf);

	if (bResult)
		nFlags |= FLAG_GETTEXT;

	return nFlags;
}

int SetText(HWND hwnd)
{
	int  nFlags = 0;
	BOOL bResult = SendMessage(hwnd, WM_SETTEXT, 0, (LPARAM)L"dummy");

	if (bResult)
		nFlags |= FLAG_SETTEXT;

	return nFlags;
}

int SendApp(HWND hwnd)
{
	int  nFlags = 0;
	BOOL bResult = SendMessage(hwnd, WM_APP, 0, 0);

	if (bResult)
		nFlags |= FLAG_APP;

	return nFlags;
}

int SendCopyData(HWND hwnd)
{
	int            nFlags = 0;
	WCHAR          szData[] = TEXT("hello");
	COPYDATASTRUCT data;

	data.dwData = 1;
	data.cbData = sizeof(szData);
	data.lpData = szData;

	BOOL bResult = SendMessage(hwnd, WM_COPYDATA, (WPARAM)0, (LPARAM)& data);

	if (bResult)
		nFlags |= FLAG_COPYDATA;

	return nFlags;
}

int CheckAccessibleObject(HWND hwnd)
{
	int          nFlags = 0;
	IAccessible* pAccessible;

	AccessibleObjectFromWindow(hwnd, OBJID_CLIENT, IID_PPV_ARGS(&pAccessible));
	if (pAccessible != NULL) {
		nFlags |= FLAG_ACCESSIBLE;
		pAccessible->Release();
	}

	return nFlags;
}

int CheckUIAutomationElement(HWND hwnd)
{
	int     nFlags = 0;
	HRESULT hr;

	CoInitialize(NULL);

	IUIAutomation* pUIAutomation;
	hr = CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pUIAutomation));
	if (FAILED(hr))
		return 0;

	IUIAutomationElement* pUIAutomationElement;
	pUIAutomation->ElementFromHandle(hwnd, &pUIAutomationElement);
	if (pUIAutomationElement != NULL) {
		nFlags |= FLAG_UIAUTOMATION;
		pUIAutomationElement->Release();
	}

	pUIAutomation->Release();
	CoUninitialize();

	return nFlags;
}

void CALLBACK Wineventproc(HWINEVENTHOOK hWinEventHook, DWORD event, HWND hwnd, LONG idObject, LONG idChild, DWORD idEventThread, DWORD dwmsEventTime)
{
	printf("event %08x\n", event);
}

HWINEVENTHOOK Start_SetWinEventHook(DWORD dwProcessId, DWORD dwThreadId)
{
	HWINEVENTHOOK hWinEventHook;

	// 32ビットプロセスから64ビットプロセスへの監視は機能する
	hWinEventHook = SetWinEventHook(EVENT_MIN, EVENT_MAX, 0, Wineventproc, dwProcessId, dwThreadId, WINEVENT_OUTOFCONTEXT);

	return hWinEventHook;
}

HWND GenProcess()
{
	WCHAR szPath[256];
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\osk.exe", szPath, sizeof(szPath) / sizeof(szPath[0]));

	PVOID pValue;
	Wow64DisableWow64FsRedirection(&pValue);
	if (1) {
		//ShellExecute(0, L"open", szPath, NULL, 0, SW_SHOW);
		ShellExecuteForShellDispatch(szPath);
	}
	else {
		STARTUPINFO         startupInfo;
		PROCESS_INFORMATION processInformation;

		ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
		startupInfo.cb = sizeof(STARTUPINFO);

		CreateProcess(szPath, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &processInformation); // ERROR_ELEVATION_REQUIRED

		CloseHandle(processInformation.hThread);
		CloseHandle(processInformation.hProcess);

		// WaitForInputIdle
	}
	Wow64RevertWow64FsRedirection(pValue);

	HWND hwnd;
	int i = 0;
	for (i = 0; i < 10; i++) {
		hwnd = FindWindow(L"OSKMainClass", NULL);
		if (hwnd != NULL)
			break;
		Sleep(100);
	}

	return hwnd;
}

BOOL ShellExecuteForShellDispatch(LPWSTR lpszPath)
{
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

	BSTR bstr = SysAllocString(lpszPath);
	hr = pShellDispatch2->ShellExecuteW(bstr, vtEmpty, vtEmpty, varOperation, varShow);
	SysFreeString(bstr);

	VariantClear(&varOperation);

	CoUninitialize();

	return SUCCEEDED(hr);
}

int DeleteProcess(DWORD dwProcessId)
{
	HRESULT hr;

	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr)) {
		printf("Failed to initialize COM library. Error code = %08x", hr);
		return FALSE;
	}

	hr = CoInitializeSecurity(
		NULL,
		-1,                          // COM negotiates service
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);
	if ((hr != S_OK) && (hr != RPC_E_TOO_LATE)) {
		//if (FAILED(hr)) {
		printf("Failed to initialize security. Error code = %08x", hr);
		CoUninitialize();
		return FALSE;
	}

	IWbemLocator* pLoc = NULL;

	hr = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)& pLoc);
	if (FAILED(hr)) {
		printf("Failed to create IWbemLocator object. Error code = %08x", hr);
		CoUninitialize();
		return FALSE;
	}

	IWbemServices* pSvc = NULL;

	// Connect to the local root\cimv2 namespace
	// and obtain pointer pSvc to make IWbemServices calls.
	hr = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"),
		NULL,
		NULL,
		0,
		NULL,
		0,
		0,
		&pSvc
	);
	if (FAILED(hr)) {
		printf("Could not connect. Error code = %08x", hr);
		pLoc->Release();
		pSvc->Release();
		CoUninitialize();
		return FALSE;
	}

	hr = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);
	if (FAILED(hr)) {
		printf("Could not set proxy blanket. Error code = %08x", hr);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	// Set up to call the Win32_Process::Create method
	BSTR ClassName = SysAllocString(L"Win32_Process");

	// YOU NEED TO CHANGE THE NUMBER VALUE OF THE HANDLE
	// (PROCESS ID) TO THE CORRECT VALUE OF THE PROCESS YOU
	// ARE TRYING TO TERMINATE (this provides a path to
	// the class instance you are tying to terminate).

	WCHAR szName[256];
	WCHAR szFormat[] = L"Win32_Process.Handle=\"%d\"";
	StringCchPrintf(szName, ARRAYSIZE(szName), szFormat, dwProcessId);
	BSTR ClassNameInstance = SysAllocString(szName);

	BSTR MethodName = SysAllocString(L"Terminate");
	BSTR ParameterName = SysAllocString(L"Reason");

	IWbemClassObject* pClass = NULL;
	hr = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

	IWbemClassObject* pInParamsDefinition = NULL;
	IWbemClassObject* pOutMethod = NULL;
	hr = pClass->GetMethod(MethodName, 0,
		&pInParamsDefinition, &pOutMethod);
	if (FAILED(hr)) {
		printf("Could not get the method. Error code = %08x", hr);
	}

	IWbemClassObject* pClassInstance = NULL;
	hr = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

	// Create the values for the in parameters
	VARIANT pcVal;
	VariantInit(&pcVal);
	V_VT(&pcVal) = VT_I4;

	// Store the value for the in parameters
	hr = pClassInstance->Put(L"Reason", 0,
		&pcVal, 0);

	// Execute Method
	hr = pSvc->ExecMethod(ClassNameInstance, MethodName, 0,
		NULL, pClassInstance, NULL, NULL); // WBEM_E_NOT_FOUND
	if (FAILED(hr)) {
		printf("Could not execute method. Error code = %08x", hr);
		VariantClear(&pcVal);
		SysFreeString(ClassName);
		SysFreeString(MethodName);
		pClass->Release();
		pInParamsDefinition->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return FALSE;
	}


	// Clean up
	//--------------------------
	VariantClear(&pcVal);
	SysFreeString(ClassName);
	SysFreeString(MethodName);
	pClass->Release();
	pInParamsDefinition->Release();
	pLoc->Release();
	pSvc->Release();
	CoUninitialize();
	return 0;
}
