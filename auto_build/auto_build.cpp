#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include <strsafe.h>

#define REPOSITORY_NAME L"test"
#define LOG_NAME L"build_log.txt"

void ScanFolder(LPWSTR lpszFolderPath, BOOL bSubFolder);
void StartProcess(LPWSTR lpszFolderPath, LPWSTR lpszFileName);
void GetMSBuildPath(LPWSTR lpszPath, DWORD dwSize);
LPWSTR GetFolderName(LPWSTR lpszFolderPath);

// 自動でvcxprojをコンパイルしていく。デスクトップ直下にリポジトリがあるものと仮定している

int main()
{
	LPWSTR lpsz;
	WCHAR  szFolderPath[MAX_PATH];

	SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &lpsz);
	StringCchPrintf(szFolderPath, ARRAYSIZE(szFolderPath), L"%s\\%s", lpsz, REPOSITORY_NAME);

	ScanFolder(szFolderPath, FALSE);

	CoTaskMemFree(lpsz);

	MessageBox(0, L"終了します。", L"OK", 0);
}

void ScanFolder(LPWSTR lpszFolderPath, BOOL bSubFolder)
{
	WCHAR           szFindPath[MAX_PATH];
	HANDLE          hFindFile;
	WIN32_FIND_DATA findData;

	StringCchPrintf(szFindPath, ARRAYSIZE(szFindPath), L"%s\\%s", lpszFolderPath, L"*");
	hFindFile = FindFirstFile(szFindPath, &findData);

	do {
		LPWSTR lpsz = findData.cFileName;
		if (lstrcmp(lpsz, L"..") != 0 && lstrcmp(lpsz, L".") != 0 && lstrcmp(lpsz, L"auto_build") != 0 && lstrcmp(lpsz, L"auto_exec") != 0) {
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				WCHAR szNewFolderPath[MAX_PATH];
				StringCchPrintf(szNewFolderPath, ARRAYSIZE(szNewFolderPath), L"%s\\%s", lpszFolderPath, findData.cFileName);
				if (bSubFolder)
					StartProcess(szNewFolderPath, findData.cFileName);
				else
					ScanFolder(szNewFolderPath, TRUE);
			}
		}
	} while (FindNextFile(hFindFile, &findData));

	FindClose(hFindFile);
}

// BOMなしのUTF-8のソースファイルは、ビルドに失敗することに注意。
// このため、全てのファイルはBOMありのUTF-8ファイル。
void StartProcess(LPWSTR lpszFolderPath, LPWSTR lpszFileName)
{
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;
	HANDLE              hFileOut;
	HANDLE              hRedirect;
	WCHAR               szModuleName[1024];
	WCHAR               szCmdLine[1024];

	GetMSBuildPath(szModuleName, ARRAYSIZE(szModuleName));
	if (GetFileAttributes(szModuleName) == INVALID_FILE_ATTRIBUTES) {
		printf("MSBuild.exeが見つかりません。");
		return;
	}

	LPWSTR lpsz = GetFolderName(lpszFolderPath);
	DWORD dwWriteByte;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY);
	WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), lpsz, lstrlen(lpsz), &dwWriteByte, NULL);

	StringCchPrintf(szCmdLine, ARRAYSIZE(szCmdLine), L"%s\\%s.vcxproj", lpszFolderPath, lpszFileName);
	StringCchCat(szCmdLine, ARRAYSIZE(szCmdLine), L" /t:Rebuild /p:Configuration=Release");
	StringCchCat(szCmdLine, ARRAYSIZE(szCmdLine), L" /p:VisualStudioVersion=16.0");
	// StringCchCat(szCmdLine, ARRAYSIZE(szCmdLine), L" -fileLoggerParameters:Encoding=UTF-8");

	hFileOut = CreateFile(LOG_NAME, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DuplicateHandle(GetCurrentProcess(), hFileOut, GetCurrentProcess(), &hRedirect, 0, TRUE, DUPLICATE_SAME_ACCESS);

	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.dwFlags = STARTF_USESTDHANDLES;
	startupInfo.hStdOutput = hRedirect;

	CreateProcess(szModuleName,
		szCmdLine, NULL, NULL, TRUE,
		CREATE_NO_WINDOW, NULL, lpszFolderPath, &startupInfo, &processInformation);

	WaitForSingleObject(processInformation.hProcess, INFINITE);
	// GetExitCodeProcess(processInformation.hProcess);

	StringCchPrintf(szModuleName, ARRAYSIZE(szModuleName), L"%s\\%s.exe", lpszFolderPath, lpszFileName);
	if (GetFileAttributes(szModuleName) == INVALID_FILE_ATTRIBUTES) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
		WCHAR szData[MAX_PATH];
		StringCchPrintf(szData, ARRAYSIZE(szData), L" ビルド失敗");

		DWORD dwWriteByte;
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), szData, lstrlen(szData), &dwWriteByte, NULL);
	}

	LPCWSTR lpszReturn = L"\n";
	WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), lpszReturn, lstrlen(lpszReturn), &dwWriteByte, NULL);

	CloseHandle(hFileOut);
	CloseHandle(hRedirect);
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
}

void GetMSBuildPath(LPWSTR lpszPath, DWORD dwSize)
{
	StringCchCopy(lpszPath, dwSize, L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe");
}

LPWSTR GetFolderName(LPWSTR lpszFolderPath)
{
	int i;
	int n = 0;

	for (i = lstrlen(lpszFolderPath) - 1; i > 0; i--) {
		if (lpszFolderPath[i] == '\\') {
			if (++n == 2)
				return &lpszFolderPath[i + 1];
		}
	}

	return lpszFolderPath;
}