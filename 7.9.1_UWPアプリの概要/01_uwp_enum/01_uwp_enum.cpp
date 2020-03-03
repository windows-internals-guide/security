#include <windows.h>
#include <strsafe.h>
#include <psapi.h>
#include <roapi.h>
#include <winstring.h>

#pragma comment (lib, "RuntimeObject.lib")

#include <windows.system.diagnostics.h>
using namespace ABI::Windows::System::Diagnostics;

BOOL IsModuleLoaded(LPCWSTR lpszModuleName);
void EnumProcessName(IProcessDiagnosticInfoStatics2* pStatics2);
BOOL IsUWPProcess(IProcessDiagnosticInfo* pDiagnosticInfo);
void GetUWPProcessName(IProcessDiagnosticInfo* pDiagnosticInfo, LPWSTR lpszName, DWORD dwBufferSize);

// 実行中プロセスからUWPアプリのものを確認

int main()
{
	HRESULT hr;

	hr = RoInitialize(RO_INIT_SINGLETHREADED);
	if (FAILED(hr)) {
		return -1;
	}

	HSTRING hString;
	HSTRING_HEADER header = {};
	LPCWSTR lpszSource = L"Windows.System.Diagnostics.ProcessDiagnosticInfo";

	hr = WindowsCreateStringReference(lpszSource, lstrlen(lpszSource), &header, &hString);
	if (hString == NULL || FAILED(hr)) {
		RoUninitialize();
		return -1;
	}

	IProcessDiagnosticInfoStatics2* pStatics2;

	hr = RoGetActivationFactory(hString, IID_PPV_ARGS(&pStatics2));

	if (FAILED(hr)) {
		printf("RoGetActivationFactoryに失敗した。 %08x", hr);
		RoUninitialize();
		return -1;
	}

	int nExitCode = -1;

#if 1
	if (IsModuleLoaded(L"Windows.System.Diagnostics.dll")) {
		printf("Windows.System.Diagnostics.dllがロードされていることを確認");
		nExitCode = 0;
		// IsImmersiveProcess(GetCurrentProcess());
	}
	else
		printf("Windowランタイムがロードされていない");
#else
	EnumProcessName(pStatics2);
	nExitCode = 0;
#endif

	pStatics2->Release();
	RoUninitialize();

	return nExitCode;
}

BOOL IsModuleLoaded(LPCWSTR lpszModuleName)
{
	HMODULE hModules[1024];
	DWORD   i, dwModuleCount, dwSize;
	WCHAR   szModuleName[MAX_PATH];

	EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &dwSize);
	dwModuleCount = dwSize / sizeof(DWORD);

	for (i = 0; i < dwModuleCount; i++) {
		GetModuleBaseName(GetCurrentProcess(), hModules[i], szModuleName, ARRAYSIZE(szModuleName));
		if (lstrcmp(lpszModuleName, szModuleName))
			return TRUE;
	}

	return FALSE;
}

#if 1

void EnumProcessName(IProcessDiagnosticInfoStatics2 * pStatics2)
{
	DWORD                   dwProcessIds[1024];
	DWORD                   i, dwProcessCount, dwSize;
	IProcessDiagnosticInfo* pDiagnosticInfo;

	EnumProcesses(dwProcessIds, sizeof(dwProcessIds), &dwSize);
	dwProcessCount = dwSize / sizeof(DWORD);

	for (i = 0; i < dwProcessCount; i++) {
		pStatics2->TryGetForProcessId(dwProcessIds[i], &pDiagnosticInfo);
		if (pDiagnosticInfo == NULL)
			continue;

		if (IsUWPProcess(pDiagnosticInfo)) {
			WCHAR szName[256];
			GetUWPProcessName(pDiagnosticInfo, szName, ARRAYSIZE(szName));
			printf("%ws\n", szName);
		}
		pDiagnosticInfo->Release();
	}
}

BOOL IsUWPProcess(IProcessDiagnosticInfo* pDiagnosticInfo)
{
	IProcessDiagnosticInfo2* pDiagnosticInfo2;

	pDiagnosticInfo->QueryInterface(IID_PPV_ARGS(&pDiagnosticInfo2));
	if (pDiagnosticInfo2 == NULL)
		return FALSE;

	boolean value;
	pDiagnosticInfo2->get_IsPackaged(&value);

	return value;
}

void GetUWPProcessName(IProcessDiagnosticInfo* pDiagnosticInfo, LPWSTR lpszName, DWORD dwBufferSize)
{
	HSTRING hString;
	UINT32  uLength;

	pDiagnosticInfo->get_ExecutableFileName(&hString);

	StringCchCopy(lpszName, dwBufferSize, WindowsGetStringRawBuffer(hString, &uLength));

	WindowsDeleteString(hString);
}

#else

void EnumProcessName(IProcessDiagnosticInfoStatics2* pStatics2)
{
	DWORD  dwProcessIds[1024];
	DWORD  i, dwProcessCount, dwSize;
	HANDLE hProcess;

	EnumProcesses(dwProcessIds, sizeof(dwProcessIds), &dwSize);
	dwProcessCount = dwSize / sizeof(DWORD);

	for (i = 0; i < dwProcessCount; i++) {
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessIds[i]);
		if (hProcess == NULL)
			continue;

		if (IsImmersiveProcess(hProcess)) {
			WCHAR szName[256];
			DWORD dwBufferSize = ARRAYSIZE(szName);
			QueryFullProcessImageName(hProcess, 0, szName, &dwBufferSize);
			printf("%ws\n", szName);
		}

		CloseHandle(hProcess);
	}
}

#endif