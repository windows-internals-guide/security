#include <windows.h>
#include <strsafe.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "userenv.lib")

class CAppContainer {
public:
	CAppContainer();
	~CAppContainer();
	HRESULT Create();
	HANDLE RunAsAppContainerProcess(LPWSTR lpszKey);
	void SetCapabilitySid(PSID pSidArray[], DWORD dwSidCount);
	void SetCapabilityWellKnownSid(WELL_KNOWN_SID_TYPE sidTypeArray[], DWORD dwSidCount);
	void FreeCapabilitySid();
	PSID GetAppContainerSid();
	void EnableHandleInheritance();

private:
	PSID  m_pSidAppContainer;
	WCHAR m_szContainerName[256];
	PSID_AND_ATTRIBUTES m_pSidAttributes;
	DWORD m_dwSidCount;
	BOOL m_bHandleInheritance;
};

int CheckAppContainerState();
BOOL IsRestrictedProcess();

// アプリコンテナープロセスを制限して実行する。CreateProcessは成功するが、新規プロセスは作成されていない。

int main()
{
	WCHAR szKey[] = L"restart-key";

	if (lstrcmp(GetCommandLine(), szKey) == 0) {
		return CheckAppContainerState();
	}

	CAppContainer appContainer;

	HRESULT hr = appContainer.Create();
	if (FAILED(hr)) {
		printf("アプリコンテナーの作成に失敗 %08x", hr);
		return -1;
	}

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == 0) {
			printf("プロセスが制限されていることを確認");
			nExitCode = 0;
		}
		else
			printf("プロセスは制限されていない");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗");
	
	return nExitCode;
}

int CheckAppContainerState()
{
	if (!IsRestrictedProcess())
		return -1;

	WCHAR szFilePath[MAX_PATH];
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32", szFilePath, sizeof(szFilePath) / sizeof(szFilePath[0]));

	PSECURITY_DESCRIPTOR pSecurityDescriptor;
	if (GetNamedSecurityInfo(szFilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSecurityDescriptor) != ERROR_SUCCESS)
		return -1;
	LocalFree(pSecurityDescriptor);

	return 0;
}

BOOL IsRestrictedProcess()
{
	DWORD  dwLength = 0;
	LPBYTE pAttributes;
	HANDLE hToken;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

	GetTokenInformation(hToken, TokenSecurityAttributes, NULL, 0, &dwLength);
	pAttributes = (LPBYTE)LocalAlloc(LPTR, dwLength);
	GetTokenInformation(hToken, TokenSecurityAttributes, pAttributes, dwLength, &dwLength);

	CloseHandle(hToken);

	LPCWSTR lpszAttrName[] = {
		L"WIN://NOALLAPPPKG"
	};
	int i, j;
	int nCount = sizeof(lpszAttrName) / sizeof(lpszAttrName[0]);
	LPBYTE lp;

	for (i = 0; i < nCount; i++) {
		int nLen = lstrlen(lpszAttrName[i]);
		DWORD dwAttrSize = lstrlen(lpszAttrName[i]) * sizeof(WCHAR);
		for (j = 0; j + dwAttrSize < dwLength; j += 2) {
			lp = (LPBYTE)pAttributes + j;
			if (CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, lpszAttrName[i], nLen, (LPWSTR)lp, nLen) - 2 == 0) {
				LocalFree(pAttributes);
				return TRUE;
			}
		}
	}

	LocalFree(pAttributes);

	return FALSE;
}


// CAppContainer


CAppContainer::CAppContainer()
{
	m_pSidAppContainer = NULL;
	m_szContainerName[0] = '\0';
	m_pSidAttributes = NULL;
	m_dwSidCount = 0;
	m_bHandleInheritance = FALSE;
}

CAppContainer::~CAppContainer()
{
	if (m_szContainerName[0] != '\0')
		DeleteAppContainerProfile(m_szContainerName);

	if (m_pSidAppContainer != NULL)
		FreeSid(m_pSidAppContainer);
}

HRESULT CAppContainer::Create()
{
	HRESULT hr;

	StringCchCopy(m_szContainerName, ARRAYSIZE(m_szContainerName), L"ContainerName");

	hr = CreateAppContainerProfile(m_szContainerName, L"DisplayName", L"Description", 0, 0, &m_pSidAppContainer);
	if (FAILED(hr)) {
		if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
			hr = DeriveAppContainerSidFromAppContainerName(m_szContainerName, &m_pSidAppContainer);
		}
	}

	return hr;
}

HANDLE CAppContainer::RunAsAppContainerProcess(LPWSTR lpszKey)
{
	if (m_pSidAppContainer == NULL)
		return NULL;

	SECURITY_CAPABILITIES securityCapabilities;
	securityCapabilities.AppContainerSid = m_pSidAppContainer;
	securityCapabilities.Reserved = NULL;
	securityCapabilities.Capabilities = m_pSidAttributes;
	securityCapabilities.CapabilityCount = m_dwSidCount;

	STARTUPINFOEX startupInfoEx = { 0 };
	SIZE_T        size;
	InitializeProcThreadAttributeList(NULL, 2, 0, &size);
	startupInfoEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LPTR, size);
	InitializeProcThreadAttributeList(startupInfoEx.lpAttributeList, 2, 0, &size);
	UpdateProcThreadAttribute(startupInfoEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &securityCapabilities, sizeof(securityCapabilities), NULL, NULL);

	DWORD dwValue = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
	UpdateProcThreadAttribute(startupInfoEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &dwValue, sizeof(dwValue), NULL, NULL);

	WCHAR               szModuleName[MAX_PATH];
	PROCESS_INFORMATION processInformation;
	GetModuleFileName(NULL, szModuleName, MAX_PATH);
	startupInfoEx.StartupInfo.cb = sizeof(startupInfoEx);
	if (CreateProcess(szModuleName, lpszKey, NULL, NULL, m_bHandleInheritance, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)& startupInfoEx, &processInformation)) {
		CloseHandle(processInformation.hThread);
	}
	else {
		processInformation.hProcess = NULL;
	}
	
	if (startupInfoEx.lpAttributeList != NULL) {
		DeleteProcThreadAttributeList(startupInfoEx.lpAttributeList);
		LocalFree(startupInfoEx.lpAttributeList);
	}

	FreeCapabilitySid();

	return processInformation.hProcess;
}

void CAppContainer::SetCapabilitySid(PSID pSidArray[], DWORD dwSidCount)
{
	DWORD i;

	m_pSidAttributes = (PSID_AND_ATTRIBUTES)LocalAlloc(LPTR, sizeof(SID_AND_ATTRIBUTES) * dwSidCount);
	m_dwSidCount = dwSidCount;

	for (i = 0; i < dwSidCount; i++) {
		m_pSidAttributes[i].Sid = pSidArray[i];
		m_pSidAttributes[i].Attributes = SE_GROUP_ENABLED;
	}
}

void CAppContainer::SetCapabilityWellKnownSid(WELL_KNOWN_SID_TYPE sidTypeArray[], DWORD dwSidCount)
{
	DWORD i, dwSidSize;

	m_pSidAttributes = (PSID_AND_ATTRIBUTES)LocalAlloc(LPTR, sizeof(SID_AND_ATTRIBUTES) * dwSidCount);
	m_dwSidCount = dwSidCount;

	for (i = 0; i < dwSidCount; i++) {
		CreateWellKnownSid(sidTypeArray[i], NULL, NULL, &dwSidSize);
		m_pSidAttributes[i].Sid = LocalAlloc(LPTR, dwSidSize);
		CreateWellKnownSid(sidTypeArray[i], NULL, m_pSidAttributes[i].Sid, &dwSidSize);

		m_pSidAttributes[i].Attributes = SE_GROUP_ENABLED;
	}
}

void CAppContainer::FreeCapabilitySid()
{
	if (m_pSidAttributes == NULL)
		return;

	DWORD i;

	for (i = 0; i < m_dwSidCount; i++) {
		LocalFree(m_pSidAttributes[i].Sid);
	}

	if (m_pSidAttributes != NULL)
		LocalFree(m_pSidAttributes);
}

PSID CAppContainer::GetAppContainerSid()
{
	return m_pSidAppContainer;
}

void CAppContainer::EnableHandleInheritance()
{
	m_bHandleInheritance = TRUE;
}
