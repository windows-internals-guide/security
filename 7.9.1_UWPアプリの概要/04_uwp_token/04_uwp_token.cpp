#include <windows.h>
#include <strsafe.h>
#include <shobjidl.h>
#include <appmodel.h>
#include <sddl.h>

BOOL StartUWPApp(LPCWSTR lpszPackageFullName, LPDWORD lpdwProcessId);
void ExitUWPApp(LPCWSTR lpszPackageFullName);
BOOL GetPackageFullName(LPCWSTR lpszName, LPWSTR lpszPackageFullName, DWORD dwBufferSize);

BOOL IsAppContainer(HANDLE hToken);
BOOL CheckIntegrityLevel(HANDLE hToken);
BOOL CheckPrivileges(HANDLE hToken);

void PrintAppContainerSid(HANDLE hToken);
void PrintCapabilities(HANDLE hToken);
void PrintSecurityAttributes(HANDLE hToken);

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
		HANDLE hToken;
		OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		if (IsAppContainer(hToken) && CheckIntegrityLevel(hToken) && CheckPrivileges(hToken)) {
			PrintAppContainerSid(hToken);
			PrintCapabilities(hToken);
			PrintSecurityAttributes(hToken);

			nExitCode = 0;
		}
		else
			printf("トークンの情報が正しくない");

		CloseHandle(hToken);
		CloseHandle(hProcess);
	}

	ExitUWPApp(szPackageFullName);

	CoUninitialize();

	return nExitCode;
}

BOOL IsAppContainer(HANDLE hToken)
{
	DWORD dwLength;
	DWORD dwAppContainer;

	GetTokenInformation(hToken, TokenIsAppContainer, &dwAppContainer, sizeof(DWORD), &dwLength);

	return dwAppContainer == 1;
}

BOOL CheckIntegrityLevel(HANDLE hToken)
{
	DWORD                  dwLength;
	PTOKEN_MANDATORY_LABEL pMandatoryLabel;

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
	pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenIntegrityLevel, pMandatoryLabel, dwLength, &dwLength);

	DWORD dwSubAuthorityCount = *GetSidSubAuthorityCount(pMandatoryLabel->Label.Sid);
	DWORD dwRid = *GetSidSubAuthority(pMandatoryLabel->Label.Sid, dwSubAuthorityCount - 1);

	LocalFree(pMandatoryLabel);

	return dwRid == SECURITY_MANDATORY_LOW_RID;
}

BOOL CheckPrivileges(HANDLE hToken)
{
	DWORD             i, j;
	DWORD             dwLength;
	PTOKEN_PRIVILEGES pTokenPrivileges;
	WCHAR             szProgramName[256];
	LPCWSTR           lpszPrivileges[] = {
		SE_CHANGE_NOTIFY_NAME, SE_INC_WORKING_SET_NAME,
		SE_SHUTDOWN_NAME, SE_TIME_ZONE_NAME,
		SE_UNDOCK_NAME
	};
	DWORD             dwTargetPrivilegeCount = sizeof(lpszPrivileges) / sizeof(lpszPrivileges[0]);
	BOOL              bResult = FALSE;

	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength);
	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength);

	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
		dwLength = sizeof(szProgramName) / sizeof(WCHAR);
		LookupPrivilegeName(NULL, &pTokenPrivileges->Privileges[i].Luid, szProgramName, &dwLength);
		for (j = 0; j < dwTargetPrivilegeCount; j++) {
			if (lstrcmp(szProgramName, lpszPrivileges[j]) == 0)
				break;
		}

		if (j != dwTargetPrivilegeCount) {
			bResult = TRUE;
			break;
		}
	}

	LocalFree(pTokenPrivileges);

	return bResult;
}

BOOL CheckSid(PSID pSid, BOOL bAppContainerSid)
{
	if (!IsValidSid(pSid))
		return FALSE;

	PSID_IDENTIFIER_AUTHORITY pAuthority = GetSidIdentifierAuthority(pSid);
	BYTE authority[] = SECURITY_APP_PACKAGE_AUTHORITY;
	PDWORD pdwSubAuthority = GetSidSubAuthority(pSid, 0);

	if (pAuthority->Value[5] != authority[5])
		return FALSE;

	if (bAppContainerSid) {
		if (*pdwSubAuthority != SECURITY_APP_PACKAGE_BASE_RID)
			return FALSE;
	}
	else {
		if (*pdwSubAuthority != SECURITY_CAPABILITY_BASE_RID)
			return FALSE;
	}

	return TRUE;
}

void PrintAppContainerSid(HANDLE hToken)
{
	DWORD                           dwLength;
	PTOKEN_APPCONTAINER_INFORMATION pAppConteinerInfo;

	GetTokenInformation(hToken, TokenAppContainerSid, NULL, 0, &dwLength);
	pAppConteinerInfo = (PTOKEN_APPCONTAINER_INFORMATION)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenAppContainerSid, pAppConteinerInfo, dwLength, &dwLength);
	if (pAppConteinerInfo == NULL || pAppConteinerInfo->TokenAppContainer == NULL) {
		return;
	}

	if (!CheckSid(pAppConteinerInfo->TokenAppContainer, TRUE)) {
		LocalFree(pAppConteinerInfo);
		return;
	}

	printf("AppContainerSid:\n");

	LPWSTR lpszSid;
	ConvertSidToStringSid(pAppConteinerInfo->TokenAppContainer, &lpszSid);
	printf("%ws\n", lpszSid);
	LocalFree(lpszSid);

	printf("AppContainerNamedObjectPath:\n");

	WCHAR szObjectPath[MAX_PATH];
	ULONG uReturnPath;
	GetAppContainerNamedObjectPath(hToken, NULL, MAX_PATH, szObjectPath, &uReturnPath);
	printf("%ws\n", szObjectPath);

	LocalFree(pAppConteinerInfo);
}

void PrintCapabilities(HANDLE hToken)
{
	DWORD         dwLength;
	PTOKEN_GROUPS pTokenGroups;

	GetTokenInformation(hToken, TokenCapabilities, NULL, 0, &dwLength);
	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenCapabilities, pTokenGroups, dwLength, &dwLength);

	printf("Capabilities:\n");

	LPWSTR lpszSid;
	DWORD  i;
	for (i = 0; i < pTokenGroups->GroupCount; i++) {
		if (CheckSid(pTokenGroups->Groups[i].Sid, FALSE)) {
			ConvertSidToStringSid(pTokenGroups->Groups[i].Sid, &lpszSid);
			printf("%ws\n", lpszSid);
			LocalFree(lpszSid);
		}
	}

	LocalFree(pTokenGroups);
}

void PrintSecurityAttributes(HANDLE hToken)
{
	DWORD  dwLength;
	LPBYTE pAttributes;

	GetTokenInformation(hToken, TokenSecurityAttributes, NULL, 0, &dwLength);
	pAttributes = (LPBYTE)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenSecurityAttributes, pAttributes, dwLength, &dwLength);

	printf("SecurityAttributes:\n");

	LPCWSTR lpszAttrName[] = {
		L"WIN://PKG", L"WIN://SYSAPPID", L"WIN://PKGHOSTID", L"WIN://BKGD", L"TSA://ProcUnique"
	};
	int    i, j;
	int    nCount = sizeof(lpszAttrName) / sizeof(lpszAttrName[0]);
	LPBYTE lp;

	for (i = 0; i < nCount; i++) {
		int   nLen = lstrlen(lpszAttrName[i]);
		DWORD dwAttrSize = lstrlen(lpszAttrName[i]) * sizeof(WCHAR);
		for (j = 0; j + dwAttrSize < dwLength; j += 2) {
			lp = (LPBYTE)pAttributes + j;
			if (CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, lpszAttrName[i], nLen, (LPWSTR)lp, nLen) - 2 == 0) {
				printf("%ws\n", lpszAttrName[i]);
			}
		}
	}

	LocalFree(pAttributes);
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

// #define PSM_ACTIVATION_TOKEN_PACKAGED_APPLICATION 0x01
// #define PSM_ACTIVATION_TOKEN_SHARED_ENTITY 0x02
// #define PSM_ACTIVATION_TOKEN_FULL_TRUST 0x04
// #define PSM_ACTIVATION_TOKEN_NATIVE_SERVICE 0x08
// #define PSM_ACTIVATION_TOKEN_DEVELOPMENT_APP 0x10
// #define BREAKWAY_INHERITED 0x20
// TOKEN_LOWBOX 0x4000
