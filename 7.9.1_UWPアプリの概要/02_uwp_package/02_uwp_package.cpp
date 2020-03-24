#include <windows.h>
#include <stdio.h>
#include <roapi.h>
#include <winstring.h>

#include <windows.foundation.h>
using namespace ABI::Windows::Foundation;

#include <windows.foundation.collections.h>
using namespace ABI::Windows::Foundation::Collections;

#include <windows.applicationmodel.h>
using namespace ABI::Windows::ApplicationModel;

#include <windows.management.deployment.h>
using namespace ABI::Windows::Management::Deployment;

#include <windows.storage.h>
using namespace ABI::Windows::Storage;

#pragma comment (lib, "RuntimeObject.lib")

void EnumPackages(IPackageManager* pPackageManager);
void DisplayPackageInfo(IPackage* pPackage);

// インストールされているパッケージの列挙を確認

int main()
{
	HRESULT hr;

	if (!SHTestTokenMembership(NULL, DOMAIN_ALIAS_RID_ADMINS)) {
		printf("IPackageManager::FindPackagesのため管理者として実行してください。");
		return -1;
	}

	hr = RoInitialize(RO_INIT_SINGLETHREADED);
	if (FAILED(hr)) {
		return -1;
	}

	HSTRING hString;
	HSTRING_HEADER header = {};
	LPCWSTR lpszSource = L"Windows.Management.Deployment.PackageManager";

	hr = WindowsCreateStringReference(lpszSource, lstrlen(lpszSource), &header, &hString);
	if (hString == NULL || FAILED(hr)) {
		RoUninitialize();
		return -1;
	}

	IInspectable* pInspectable;

	hr = RoActivateInstance(hString, &pInspectable);
	if (FAILED(hr)) {
		printf("クラスのアクティブ化に失敗 %08x", hr);
		RoUninitialize();
		return -1;
	}

	IPackageManager* pPackageManager;

	hr = pInspectable->QueryInterface(IID_PPV_ARGS(&pPackageManager));
	if (FAILED(hr)) { // REGDB_E_CLASSNOTREG
		printf("PackageManagerを取得できない。 %08x", hr);
		pInspectable->Release();
		RoUninitialize();
		return -1;
	}

#if 1
	printf("PackageManagerを取得した。");
#else
	EnumPackages(pPackageManager);
#endif

#ifdef _DEBUG
	MessageBox(NULL, L"終了します。", L"OK", 0);
#endif

	pPackageManager->Release();
	pInspectable->Release();
	RoUninitialize();

	return 0;
}

void EnumPackages(IPackageManager* pPackageManager)
{
	IIterable<Package*>* pPackages;
	IIterator<Package*>* pPackage;
	IPackage* pCurrent;
	boolean isEnd;

	pPackageManager->FindPackages(&pPackages);
	pPackages->First(&pPackage);

	for (;;) {
		pPackage->get_Current(&pCurrent);
		DisplayPackageInfo(pCurrent);
		pCurrent->Release();

		pPackage->MoveNext(&isEnd);
		if (!isEnd)
			break;
	}

	pPackage->Release();
	pPackages->Release();
}

void DisplayPackageInfo(IPackage* pPackage)
{
	IStorageFolder* pStorage;
	IStorageItem* pItem;

	pPackage->get_InstalledLocation(&pStorage);
	if (pStorage == NULL)
		return;

	pStorage->QueryInterface(IID_PPV_ARGS(&pItem));

	HSTRING hString;
	pItem->get_Path(&hString);
	// pItem->get_Name(&hString);

	UINT32  uLength;
	LPCWSTR lpszRaw = WindowsGetStringRawBuffer(hString, &uLength);

	printf("%ws\n", lpszRaw);

	WindowsDeleteString(hString);
	pStorage->Release();
	pItem->Release();
}
