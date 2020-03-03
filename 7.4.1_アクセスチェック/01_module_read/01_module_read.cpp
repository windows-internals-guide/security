#include <windows.h>
#include <stdio.h>

// EXEファイルに対して読み取りアクセスを行う

int main()
{
	HANDLE hFile;
	WCHAR  szFileName[MAX_PATH];

	GetModuleFileName(NULL, szFileName, MAX_PATH);

	hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("ファイルをオープンできません。\n");
		return -1;
	}

	int nExitCode = -1;
	BYTE signature[2];
	DWORD dwReadByte;
	ReadFile(hFile, signature, sizeof(signature), &dwReadByte, NULL);
	// EXEファイルの先頭バイトはMZ
	if (signature[0] == 'M' && signature[1] == 'Z') {
		printf("読み取りアクセス成功");
		nExitCode = 0;
	}
	else
		printf("読み取り失敗");

	CloseHandle(hFile);

	return nExitCode;
}
