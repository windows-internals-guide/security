#include <windows.h>
#include <shlobj.h>
#include <stdio.h>

int main()
{
	HRESULT            hr;
	IOpenControlPanel* pOpenControlPanel;
	WCHAR              szPath[512] = { 0 };

	CoInitialize(NULL);

	hr = CoCreateInstance(CLSID_OpenControlPanel, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pOpenControlPanel));
	if (FAILED(hr)) {
		CoUninitialize();
		return -1;
	}

	int nExitCode = -1;

	hr = pOpenControlPanel->GetPath(L"Microsoft.CredentialManager", szPath, 512); // ::{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}
	if (SUCCEEDED(hr)) {
		printf("%ws", szPath);
		nExitCode = 0;
	}
	else {
		printf("コントロールパネルアプレットのパスを取得できない");
	}

	pOpenControlPanel->Release();
	CoUninitialize();

	return nExitCode;
}