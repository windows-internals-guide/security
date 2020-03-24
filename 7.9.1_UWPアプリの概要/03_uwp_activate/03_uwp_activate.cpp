#include <windows.h>
#include <strsafe.h>
#include <shobjidl.h>
#include <appmodel.h>

void PrintPackageId(HANDLE hProcess);
BOOL StartUWPApp(LPCWSTR lpszPackageFullName, LPDWORD lpdwProcessId);
void ExitUWPApp(LPCWSTR lpszPackageFullName);
BOOL GetPackageFullName(LPCWSTR lpszName, LPWSTR lpszPackageFullName, DWORD dwBufferSize);

// UWPアプリを起動し、アプリコンテナーの有無、整合性レベル、特権を確認

int main()
{
	WCHAR szPackageFullName[256];
	if (!GetPackageFullName(L"Microsoft.WindowsCalculator", szPackageFullName, ARRAYSIZE(szPackageFullName)))
		return -1;

	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr))
		return -1;

	DWORD dwProcessId;
	if (!StartUWPApp(szPackageFullName, &dwProcessId)) {
		printf("UWPアプリを起動できない。");
		CoUninitialize();
		return -1;
	}

	int nExitCode = -1;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
	if (hProcess != NULL) {
		PrintPackageId(hProcess);
		CloseHandle(hProcess);
		nExitCode = 0;
	}
	else
		printf("UWPプロセスの情報を取得できなかった。");

	ExitUWPApp(szPackageFullName);

	CoUninitialize();

	return nExitCode;
}

void PrintPackageId(HANDLE hProcess)
{
	PACKAGE_ID* pPackageId;
	UINT32      uBufferLength = 0;

	GetPackageId(hProcess, &uBufferLength, NULL);
	pPackageId = (PACKAGE_ID*)LocalAlloc(LPTR, uBufferLength);
	GetPackageId(hProcess, &uBufferLength, (LPBYTE)pPackageId);
	printf("Package Name: %ws\n", pPackageId->name);
	printf("Publisher: %ws\n", pPackageId->publisher);
	printf("Published ID: %ws\n", pPackageId->publisherId);
	LocalFree(pPackageId);

	LPWSTR lpszPackageFullName;
	GetPackageFullName(hProcess, &uBufferLength, NULL);
	lpszPackageFullName = (LPWSTR)LocalAlloc(LPTR, uBufferLength * sizeof(WCHAR));
	GetPackageFullName(hProcess, &uBufferLength, lpszPackageFullName);
	printf("Package Full Name: %ws\n", lpszPackageFullName);
	LocalFree(lpszPackageFullName);

	WCHAR szImageName[MAX_PATH];
	DWORD dwSize = MAX_PATH;
	QueryFullProcessImageName(hProcess, 0, szImageName, &dwSize);
	printf("ImageName: %ws\n", szImageName);
}

BOOL StartUWPApp(LPCWSTR lpszPackageFullName, LPDWORD lpdwProcessId)
{
	HRESULT                        hr;
	IApplicationActivationManager* pActivationManager = NULL;

	hr = CoCreateInstance(CLSID_ApplicationActivationManager, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pActivationManager));
	if (FAILED(hr))
		return FALSE;

	hr = CoAllowSetForegroundWindow(pActivationManager, NULL);
	if (FAILED(hr)) {
		pActivationManager->Release();
		return FALSE;
	}

	LPWSTR* lpszAppUserModelIds = NULL;

	PACKAGE_INFO_REFERENCE packageInfo;
	LONG lResult = OpenPackageInfoByFullName(lpszPackageFullName, 0, &packageInfo);
	if (lResult == ERROR_SUCCESS) {
		UINT32 uAppIDCount = 0;
		LPBYTE lpData;
		UINT32 uBufferLength = 0;

		GetPackageApplicationIds(packageInfo, &uBufferLength, NULL, &uAppIDCount);
		lpData = (LPBYTE)LocalAlloc(LPTR, uBufferLength);
		lResult = GetPackageApplicationIds(packageInfo, &uBufferLength, lpData, &uAppIDCount);

		ClosePackageInfo(packageInfo);

		lpszAppUserModelIds = (LPWSTR*)lpData;
	}
	else {
		pActivationManager->Release();
		return FALSE;
	}

	hr = pActivationManager->ActivateApplication(lpszAppUserModelIds[0], NULL, AO_NONE, lpdwProcessId);

	LocalFree(lpszAppUserModelIds);
	pActivationManager->Release();

	return SUCCEEDED(hr);
}

void ExitUWPApp(LPCWSTR lpszPackageFullName)
{
	HRESULT                hr;
	IPackageDebugSettings* pPackageDebugSettings;

	hr = CoCreateInstance(CLSID_PackageDebugSettings, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pPackageDebugSettings));
	if (FAILED(hr)) {
		return;
	}

	pPackageDebugSettings->TerminateAllProcesses(lpszPackageFullName);

	pPackageDebugSettings->Release();
}

BOOL GetPackageFullName(LPCWSTR lpszName, LPWSTR lpszPackageFullName, DWORD dwBufferSize)
{
	HKEY    hKey;
	LONG    lResult;
	DWORD   i;
	WCHAR   szName[256];
	DWORD   dwName;
	BOOL    bFound = FALSE;
	LPCWSTR lpszParentKey = L"Software\\Classes\\ActivatableClasses\\Package";
	int     nLen = lstrlen(lpszName);

	lResult = RegOpenKeyEx(HKEY_CURRENT_USER, lpszParentKey, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hKey);
	if (lResult != ERROR_SUCCESS)
		return FALSE;

	for (i = 0;; i++) {
		dwName = ARRAYSIZE(szName);
		lResult = RegEnumKeyEx(hKey, i, szName, &dwName, NULL, NULL, NULL, NULL);
		if (lResult == ERROR_SUCCESS && CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, lpszName, nLen, (LPWSTR)szName, nLen) - 2 == 0) {
			StringCchCopy(lpszPackageFullName, dwBufferSize, szName);
			bFound = TRUE;
			break;
		}
		else if (lResult == ERROR_NO_MORE_ITEMS)
			break;
	}

	RegCloseKey(hKey);

	return bFound;
}