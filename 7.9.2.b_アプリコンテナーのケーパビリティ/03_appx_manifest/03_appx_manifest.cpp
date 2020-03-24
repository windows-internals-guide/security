#include <windows.h>
#include <shlwapi.h>
#include <appxpackaging.h>
#include <strsafe.h>
#include <appmodel.h>
#include <sddl.h>
#include <tlhelp32.h>

#pragma comment (lib, "shlwapi.lib")

struct CAPABILITY_DATA {
	LPWSTR lpszName;
	PSID   pSid;
	BOOL   bDevice;
};
typedef CAPABILITY_DATA* LPCAPABILITY_DATA;

CAPABILITY_DATA g_cpabilityData[30];
int g_nCapabilityCount = 0;

HANDLE OpenProcessByFileName(LPCWSTR lpszFileName);
BOOL ReadManifestByProcessHandle(HANDLE hProcess);
BOOL ReadAppxManifest(LPWSTR lpszManifestPath);
void SetupCapabilities(IAppxManifestReader* pManifestReader);
void SetupDeviceCapabilities(IAppxManifestReader* pManifestReader);
BOOL GetRootFolderPathFromFullPackageName(LPCWSTR lpszFullPackage, LPWSTR lpszFolderPath, DWORD dwBufferSize);
BOOL GetDeviceCapabilitySidFromName(LPWSTR lpszName, PSID* ppDeviceCapabilitySid);
BOOL EnumCapabilitySubKey(LPCWSTR lpszParentKey, LPWSTR lpszName, PSID* ppDeviceCapabilitySid);
BOOL IsCapabilityIncluded(HANDLE hProcess);

// トークンがマニフェストのケーパビリティを完全に含むことを確認

int main()
{
	int    i;
	HANDLE hProcess;

	hProcess = OpenProcessByFileName(L"SearchUI.exe");
	if (hProcess == NULL)
		return -1;

	if (!ReadManifestByProcessHandle(hProcess)) {
		CloseHandle(hProcess);
		return -1;
	}

	int nExitCode = -1;
	if (IsCapabilityIncluded(hProcess)) {
		printf("トークンはマニフェストのケーパビリティを完全に含む");
#if 0
		printf("\n");
		LPWSTR lpszSid;
		for (i = 0; i < g_nCapabilityCount; i++) {
			ConvertSidToStringSid(g_cpabilityData[i].pSid, &lpszSid);
			printf("%ws %ws\n", g_cpabilityData[i].lpszName, lpszSid);
			LocalFree(lpszSid);
		}
#endif
		nExitCode = 0;
	}
	else {
		printf("マニフェストのケーパビリティをトークンが含まない");
	}

	for (i = 0; i < g_nCapabilityCount; i++) {
		CoTaskMemFree(g_cpabilityData[i].lpszName);

		if (g_cpabilityData[i].bDevice)
			FreeSid(g_cpabilityData[i].pSid);
		else
			LocalFree(g_cpabilityData[i].pSid);
	}

	CloseHandle(hProcess);

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

HANDLE OpenProcessByFileName(LPCWSTR lpszFileName)
{
	HANDLE         hSnapshot;
	DWORD          dwProcessId;
	PROCESSENTRY32 pe;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return NULL;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	dwProcessId = 0;
	do {
		if (lstrcmp(pe.szExeFile, lpszFileName) == 0) {
			dwProcessId = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
}

BOOL ReadManifestByProcessHandle(HANDLE hProcess)
{
	WCHAR szManifestPath[MAX_PATH];
	WCHAR szRootFolderPath[MAX_PATH];

#if 1
	LPWSTR lpszFullPackage;
	UINT32 uLength = 0;

	GetPackageFullName(hProcess, &uLength, NULL);
	lpszFullPackage = (LPWSTR)LocalAlloc(LPTR, uLength * sizeof(WCHAR));
	GetPackageFullName(hProcess, &uLength, lpszFullPackage);

	if (!GetRootFolderPathFromFullPackageName(lpszFullPackage, szRootFolderPath, ARRAYSIZE(szRootFolderPath))) {
		LocalFree(lpszFullPackage);
		return FALSE;
	}
	LocalFree(lpszFullPackage);
#else
	WCHAR szImageName[MAX_PATH];
	DWORD dwSize = MAX_PATH;

	QueryFullProcessImageName(hProcess, 0, szImageName, &dwSize);
	for (int i = lstrlen(szImageName) - 1; i > 0; i--) {
		if (szImageName[i] == '\\') {
			szImageName[i] = '\0';
			StringCchCopy(szRootFolderPath, ARRAYSIZE(szRootFolderPath), szImageName);
			break;
		}
	}
#endif

	StringCchPrintf(szManifestPath, ARRAYSIZE(szManifestPath), L"%s\\%s", szRootFolderPath, L"AppxManifest.xml");

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	BOOL bResult = ReadAppxManifest(szManifestPath);
	CoUninitialize();

	return bResult;
}

BOOL ReadAppxManifest(LPWSTR lpszManifestPath)
{
	HRESULT       hr = S_OK;
	IAppxFactory* pAppxFactory = NULL;
	IStream*      pStream = NULL;

	hr = SHCreateStreamOnFileEx(lpszManifestPath, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, FALSE, NULL, &pStream);
	if (FAILED((hr)))
		return FALSE;

	hr = CoCreateInstance(CLSID_AppxFactory, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pAppxFactory));
	if (FAILED((hr))) {
		pStream->Release();
		return FALSE;
	}

	IAppxManifestReader* pManifestReader;

	hr = pAppxFactory->CreateManifestReader(pStream, &pManifestReader);
	if (FAILED(hr)) {
		pStream->Release();
		pAppxFactory->Release();
		return FALSE;
	}

	SetupCapabilities(pManifestReader);
	SetupDeviceCapabilities(pManifestReader);

	pStream->Release();
	pAppxFactory->Release();
	pManifestReader->Release();

	return TRUE;
}

void SetupCapabilities(IAppxManifestReader* pManifestReader)
{
	APPX_CAPABILITIES capabilities;

	pManifestReader->GetCapabilities(&capabilities);

	struct TABLE {
		APPX_CAPABILITIES   appxCapabilities;
		WELL_KNOWN_SID_TYPE sidType;
		LPCWSTR             lpszName;
	} table[] = {
		{APPX_CAPABILITY_INTERNET_CLIENT, WinCapabilityInternetClientSid, L"Internet"},
		{APPX_CAPABILITY_INTERNET_CLIENT_SERVER, WinCapabilityInternetClientServerSid, L"InternetClient"},
		{APPX_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER, WinCapabilityPrivateNetworkClientServerSid, L"PrivateNetworkClient"},

		{APPX_CAPABILITY_DOCUMENTS_LIBRARY, WinCapabilityDocumentsLibrarySid, L"DocumentsLibrary"},
		{APPX_CAPABILITY_PICTURES_LIBRARY, WinCapabilityPicturesLibrarySid, L"PicturesLibrary"},
		{APPX_CAPABILITY_VIDEOS_LIBRARY, WinCapabilityVideosLibrarySid, L"VideosLibrary"},
		{APPX_CAPABILITY_MUSIC_LIBRARY, WinCapabilityMusicLibrarySid, L"MusicLibrary"},

		{APPX_CAPABILITY_ENTERPRISE_AUTHENTICATION, WinCapabilityEnterpriseAuthenticationSid, L"EnterpriseAuthentication"},
		{APPX_CAPABILITY_SHARED_USER_CERTIFICATES, WinCapabilitySharedUserCertificatesSid, L"SharedUserCertificates"},
		{APPX_CAPABILITY_REMOVABLE_STORAGE, WinCapabilityRemovableStorageSid, L"RemovableStorage"},

		{APPX_CAPABILITY_APPOINTMENTS, WinCapabilityAppointmentsSid, L"Appointments"},
		{APPX_CAPABILITY_CONTACTS, WinCapabilityContactsSid, L"Contacts"},
	};
	int               i;
	int               nCount = sizeof(table) / sizeof(table[0]);
	LPWSTR            lpszName;
	PSID              pSid;
	DWORD             dwSize;
	LPCAPABILITY_DATA lpData;

	for (i = 0; i < nCount; i++) {
		if (!(capabilities & table[i].appxCapabilities))
			continue;

		dwSize = (lstrlen(table[i].lpszName) + 1) * sizeof(WCHAR);
		lpszName = (LPWSTR)CoTaskMemAlloc(dwSize);
		CopyMemory(lpszName, table[i].lpszName, dwSize);

		CreateWellKnownSid(table[i].sidType, NULL, NULL, &dwSize);
		pSid = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
		CreateWellKnownSid(table[i].sidType, NULL, pSid, &dwSize);

		lpData = (LPCAPABILITY_DATA)& g_cpabilityData[g_nCapabilityCount];
		lpData->lpszName = lpszName;
		lpData->pSid = pSid;
		lpData->bDevice = FALSE;

		g_nCapabilityCount++;
	}
}

void SetupDeviceCapabilities(IAppxManifestReader* pManifestReader)
{
	IAppxManifestDeviceCapabilitiesEnumerator* pEnumerator;
	BOOL                                       bData;
	LPWSTR                                     lpszCapability;
	PSID                                       pSid;
	LPCAPABILITY_DATA                          lpData;

	pManifestReader->GetDeviceCapabilities(&pEnumerator);

	pEnumerator->GetHasCurrent(&bData);
	for (; bData;) {
		lpszCapability = NULL;
		pEnumerator->GetCurrent(&lpszCapability);
		GetDeviceCapabilitySidFromName(lpszCapability, &pSid);

		lpData = (LPCAPABILITY_DATA)& g_cpabilityData[g_nCapabilityCount];
		lpData->lpszName = lpszCapability;
		lpData->pSid = pSid;
		lpData->bDevice = TRUE;

		g_nCapabilityCount++;

		pEnumerator->MoveNext(&bData);
	}

	pEnumerator->Release();
}

BOOL GetRootFolderPathFromFullPackageName(LPCWSTR lpszFullPackage, LPWSTR lpszFolderPath, DWORD dwBufferSize)
{
	WCHAR   szKey[1024];
	HKEY    hKey;
	LONG    lResult;
	BOOL    bFound = FALSE;
	LPCWSTR lpszParentKey = L"Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages";

	StringCchPrintf(szKey, ARRAYSIZE(szKey), L"%s\\%s", lpszParentKey, lpszFullPackage);

	lResult = RegOpenKeyEx(HKEY_CLASSES_ROOT, szKey, 0, KEY_QUERY_VALUE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return FALSE;

	RegQueryValueEx(hKey, L"PackageRootFolder", NULL, NULL, (LPBYTE)lpszFolderPath, &dwBufferSize);

	RegCloseKey(hKey);

	return TRUE;
}

BOOL GetDeviceCapabilitySidFromName(LPWSTR lpszName, PSID* ppDeviceCapabilitySid)
{
	HKEY    hKey;
	LONG    lResult;
	DWORD   i;
	WCHAR   szDeviceClass[256];
	DWORD   dwName;
	BOOL    bFound = FALSE;
	LPCWSTR lpszParentKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\CapabilityMappings";

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpszParentKey, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hKey);
	if (lResult != ERROR_SUCCESS)
		return FALSE;

	for (i = 0;; i++) {
		dwName = ARRAYSIZE(szDeviceClass);
		lResult = RegEnumKeyEx(hKey, i, szDeviceClass, &dwName, NULL, NULL, NULL, NULL);
		if (lResult == ERROR_SUCCESS && lstrcmpi(lpszName, szDeviceClass) == 0) {
			if (EnumCapabilitySubKey(lpszParentKey, lpszName, ppDeviceCapabilitySid)) {
				bFound = TRUE;
				break;
			}
		}
		else if (lResult == ERROR_NO_MORE_ITEMS)
			break;
	}

	RegCloseKey(hKey);

	return bFound;
}

BOOL EnumCapabilitySubKey(LPCWSTR lpszParentKey, LPWSTR lpszName, PSID* ppDeviceCapabilitySid)
{
	WCHAR szKey[1024];
	HKEY  hKey;
	LONG  lResult;
	DWORD i;
	WCHAR szGuid[256];
	DWORD dwName;
	BOOL  bFound = FALSE;

	StringCchPrintf(szKey, ARRAYSIZE(szKey), L"%s\\%s", lpszParentKey, lpszName);

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hKey);
	if (lResult != ERROR_SUCCESS)
		return FALSE;

	for (i = 0;; i++) {
		dwName = ARRAYSIZE(szGuid);
		lResult = RegEnumKeyEx(hKey, i, szGuid, &dwName, NULL, NULL, NULL, NULL);
		if (lResult == ERROR_SUCCESS) {
			GUID guid;
			if (FAILED(IIDFromString(szGuid, &guid)))
				continue;

			LPDWORD                  lpdw = (LPDWORD)& guid;
			SID_IDENTIFIER_AUTHORITY identifierAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
			AllocateAndInitializeSid(&identifierAuthority, SECURITY_CAPABILITY_RID_COUNT, SECURITY_CAPABILITY_BASE_RID,
				*lpdw, *(lpdw + 1), *(lpdw + 2), *(lpdw + 3), 0, 0, 0, ppDeviceCapabilitySid);

			bFound = TRUE;
			break;
		}
		else if (lResult == ERROR_NO_MORE_ITEMS)
			break;
	}

	RegCloseKey(hKey);

	return bFound;
}

BOOL IsCapabilityIncluded(HANDLE hProcess)
{
	int    i;
	HANDLE hToken, hTokenImpersonation;
	BOOL   bResult;

	OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hTokenImpersonation);

	for (i = 0; i < g_nCapabilityCount; i++) {
		CheckTokenCapability(hTokenImpersonation, g_cpabilityData[i].pSid, &bResult);
		if (!bResult)
			break;
	}

	CloseHandle(hToken);
	CloseHandle(hTokenImpersonation);

	return i == g_nCapabilityCount;
}