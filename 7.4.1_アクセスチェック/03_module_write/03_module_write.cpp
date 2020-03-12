#include <windows.h>
#include <stdio.h>

// EXEファイルに対して読み取りアクセスを指定したうえで、書き込みアクセスを行う

int main()
{
	HANDLE hFile;
	WCHAR  szFileName[MAX_PATH];

	GetModuleFileName(NULL, szFileName, MAX_PATH);

	hFile = CreateFile(szFileName, FILE_READ_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("ファイルをオープンできなかった %d", GetLastError());
		return -1;
	}

	int nExitCode = -1;
	char dummy[] = "dummy";
	DWORD dwWriteByte;
	if (!WriteFile(hFile, dummy, sizeof(dummy), &dwWriteByte, NULL)) {
		printf("書き込みアクセスが拒否されるのは正しい %d", GetLastError());
		nExitCode = 0;
	}
	else
		printf("書き込めてしまった");

	CloseHandle(hFile);

	return nExitCode;
}
