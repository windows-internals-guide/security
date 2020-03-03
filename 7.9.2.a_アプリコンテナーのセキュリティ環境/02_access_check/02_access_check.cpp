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
PSID CreateSid(DWORD dwType);
void AccessCheckForAppContainer(LPWSTR lpszFilePath, PSID pSid, LPBOOL lpbResult);
void FormatPath(LPWSTR lpszFilePath, PSID pSidAppContainer, int nFileNo);

// アプリコンテナー環境下のアクセスチェックで、NULL DACLのアクセス許可や、グループのSIDが使用されないことを確認

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
	
	WELL_KNOWN_SID_TYPE sidTypeArray[] = { WinCapabilityPicturesLibrarySid };
	appContainer.SetCapabilityWellKnownSid(sidTypeArray, ARRAYSIZE(sidTypeArray));

	int    nExitCode = -1;
	HANDLE hRestartProcess = appContainer.RunAsAppContainerProcess(szKey);
	if (hRestartProcess != NULL) {
		DWORD dwExitCode;
		WaitForSingleObject(hRestartProcess, 4000);
		GetExitCodeProcess(hRestartProcess, &dwExitCode);
		if (dwExitCode == 0) {
			printf("アクセスチェックの結果は正しい");
			nExitCode = 0;
		}
		else
			printf("アクセスチェックの結果は正しくない");
		CloseHandle(hRestartProcess);
	}
	else
		printf("プロセスの作成に失敗。");

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	return nExitCode;
}

#define SID_NULL 0x01
#define SID_USERS 0x02
#define SID_APPCONTAINER 0x04
#define SID_CAPABILITY 0x08
#define SID_ALLPACKAGE 0x10

// CREATE_NO_WINDOW指定なら、printf見えない

int CheckAppContainerState()
{
	BOOL bResult;
	DWORD dwFlags = 0;
	WCHAR szPath[MAX_PATH];
	PSID pSidUsers = CreateSid(SID_USERS);
	PSID pSidAppContainer = CreateSid(SID_APPCONTAINER);
	PSID pSidCapability = CreateSid(SID_CAPABILITY);
	PSID pSidAllPackages = CreateSid(SID_ALLPACKAGE);

	CheckTokenMembershipEx(NULL, pSidUsers, CTMF_INCLUDE_APPCONTAINER, &bResult); if (bResult) dwFlags |= SID_USERS;
	CheckTokenMembershipEx(NULL, pSidAppContainer, CTMF_INCLUDE_APPCONTAINER, &bResult); if (bResult) dwFlags |= SID_APPCONTAINER;
	CheckTokenMembershipEx(NULL, pSidCapability, CTMF_INCLUDE_APPCONTAINER, &bResult); if (bResult) dwFlags |= SID_CAPABILITY;
	CheckTokenMembershipEx(NULL, pSidAllPackages, CTMF_INCLUDE_APPCONTAINER, &bResult); if (bResult) dwFlags |= SID_ALLPACKAGE;

	printf("%x \n", dwFlags);

	dwFlags = 0;
	FormatPath(szPath, pSidAppContainer, 0); AccessCheckForAppContainer(szPath, NULL, &bResult); if (bResult) dwFlags |= SID_NULL;
	FormatPath(szPath, pSidAppContainer, 1); AccessCheckForAppContainer(szPath, pSidUsers, &bResult); if (bResult) dwFlags |= SID_USERS;
	FormatPath(szPath, pSidAppContainer, 2); AccessCheckForAppContainer(szPath, pSidAppContainer, &bResult); if (bResult) dwFlags |= SID_APPCONTAINER;
	FormatPath(szPath, pSidAppContainer, 3); AccessCheckForAppContainer(szPath, pSidCapability, &bResult); if (bResult) dwFlags |= SID_CAPABILITY;
	FormatPath(szPath, pSidAppContainer, 4); AccessCheckForAppContainer(szPath, pSidAllPackages, &bResult); if (bResult) dwFlags |= SID_ALLPACKAGE;

	printf("%x \n", dwFlags);
	printf("%x \n", SID_APPCONTAINER | SID_CAPABILITY | SID_ALLPACKAGE);

	LocalFree(pSidUsers);
	LocalFree(pSidAppContainer);
	LocalFree(pSidCapability);
	LocalFree(pSidAllPackages);

	return 0;
}

PSID CreateSid(DWORD dwType)
{
	PSID pSidReturn = NULL;

	if (dwType == SID_APPCONTAINER) {
		DWORD dwLength;
		PTOKEN_APPCONTAINER_INFORMATION pAppConteiner;
		HANDLE hToken;
		OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

		GetTokenInformation(hToken, TokenAppContainerSid, NULL, 0, &dwLength);
		pAppConteiner = (PTOKEN_APPCONTAINER_INFORMATION)LocalAlloc(LPTR, dwLength);
		GetTokenInformation(hToken, TokenAppContainerSid, pAppConteiner, dwLength, &dwLength);
		if (pAppConteiner == NULL || pAppConteiner->TokenAppContainer == NULL) {
			return NULL;
		}

		dwLength = GetLengthSid(pAppConteiner->TokenAppContainer);
		pSidReturn = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
		CopySid(dwLength, pSidReturn, pAppConteiner->TokenAppContainer);

		LocalFree(pAppConteiner);
		CloseHandle(hToken);
	}
	else if (dwType == SID_CAPABILITY) { // ケーパビリティSIDをWinMainで指定しないとエラー
		DWORD         dwLength;
		PTOKEN_GROUPS pTokenGroups;
		HANDLE hToken;
		OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

		GetTokenInformation(hToken, TokenCapabilities, NULL, 0, &dwLength);
		pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwLength);
		GetTokenInformation(hToken, TokenCapabilities, pTokenGroups, dwLength, &dwLength);

		dwLength = GetLengthSid(pTokenGroups->Groups[0].Sid);
		pSidReturn = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
		CopySid(dwLength, pSidReturn, pTokenGroups->Groups[0].Sid);

		LocalFree(pTokenGroups);
		CloseHandle(hToken);
	}
	else if (dwType == SID_USERS) {
		DWORD dwSidSize = SECURITY_MAX_SID_SIZE;
		pSidReturn = (PSID)LocalAlloc(LPTR, dwSidSize);
		CreateWellKnownSid(WinBuiltinUsersSid, NULL, pSidReturn, &dwSidSize);
	}
	else if (dwType == SID_ALLPACKAGE) {
		WCHAR        szDomainName[256];
		DWORD        dwSizeDomain = sizeof(szDomainName) / sizeof(WCHAR);
		DWORD        dwSizeSid = 0;
		SID_NAME_USE sidName;
		LPCWSTR      lpszName = L"ALL APPLICATION PACKAGES";

		LookupAccountName(NULL, lpszName, NULL, &dwSizeSid, szDomainName, &dwSizeDomain, &sidName);
		pSidReturn = (PSID)LocalAlloc(LPTR, dwSizeSid);
		LookupAccountName(NULL, lpszName, pSidReturn, &dwSizeSid, szDomainName, &dwSizeDomain, &sidName);
	}

	return pSidReturn;
}

void AccessCheckForAppContainer(LPWSTR lpszFilePath, PSID pSid, LPBOOL lpbResult)
{
	DWORD       dwLength;
	HANDLE      hToken;
	PTOKEN_USER pTokenUser = NULL;
	PACL        pDacl = NULL;

	if (pSid != NULL) {
		OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
		pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
		GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength);
		CloseHandle(hToken);

		pDacl = (PACL)LocalAlloc(LPTR, 1024);
		DWORD dwDesiredAccess = GENERIC_ALL;

		InitializeAcl(pDacl, 1024, ACL_REVISION);

		AddAccessAllowedAce(pDacl, ACL_REVISION, dwDesiredAccess, pTokenUser->User.Sid);
		AddAccessAllowedAce(pDacl, ACL_REVISION, dwDesiredAccess, pSid);
	}

	HANDLE hFile = CreateFile(lpszFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	CloseHandle(hFile);

	SetNamedSecurityInfo(lpszFilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL);

	hFile = CreateFile(lpszFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	*lpbResult = GetLastError() == ERROR_SUCCESS;
	CloseHandle(hFile);

	if (pDacl != NULL) {
		LocalFree(pDacl);
	}

	if (pTokenUser != NULL) {
		LocalFree(pTokenUser);
	}
}

void FormatPath(LPWSTR lpszFilePath, PSID pSidAppContainer, int nFileNo)
{
	LPWSTR lpszSid;
	ConvertSidToStringSid(pSidAppContainer, &lpszSid);

	LPWSTR lpszPath;
	GetAppContainerFolderPath(lpszSid, &lpszPath);

	StringCchPrintf(lpszFilePath, MAX_PATH, L"%s\\%d.txt", lpszPath, nFileNo);

	CoTaskMemFree(lpszPath);
	LocalFree(lpszSid);
}


// CAppContainer


CAppContainer::CAppContainer()
{
	m_pSidAppContainer = NULL;
	m_szContainerName[0] = '\0';
	m_pSidAttributes = NULL;
	m_dwSidCount = 0;
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
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	startupInfoEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LPTR, size);
	InitializeProcThreadAttributeList(startupInfoEx.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(startupInfoEx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &securityCapabilities, sizeof(securityCapabilities), NULL, NULL);

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
