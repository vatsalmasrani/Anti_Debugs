#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <iostream>
using namespace std;
BOOL read_peb(HANDLE hProc);

  
int get_done(DWORD pid) {
	LPCSTR lpName = "system";

HANDLE htoken;
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&htoken)) {
		return -1;
	}
		TOKEN_PRIVILEGES tkp = {0};
		if(LookupPrivilegeValue(NULL,lpName,&tkp.Privileges[0].Luid)) {
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //get Current Luid and change the array
			AdjustTokenPrivileges(htoken,FALSE,&tkp,0,0,0);
		
			return 1;
		}
	
	PROCESSENTRY32  pe32_entry;
	bool get_pid = false;

pe32_entry.dwSize = sizeof(PROCESSENTRY32);

HANDLE hSnapShot;
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
BOOL nextProcess = Process32First(hSnapShot,&pe32_entry);
while(nextProcess) {
	if(pe32_entry.th32ProcessID == pid) {
		get_pid = true;
		break;
	}
	nextProcess = Process32Next(hSnapShot,&pe32_entry);
}
	if(get_pid) {
		cout << pe32_entry.szExeFile;
		HANDLE hProcess;
		hProcess = OpenProcess(PROCESS_VM_READ,FALSE,pe32_entry.th32ProcessID);
		read_peb(hProcess);
	}



	CloseHandle(hSnapShot);
	return 0;
}

BOOL read_peb(HANDLE hProc) {
	typedef LONG (WINAPI NTQUERYINFO) (HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
	NTQUERYINFO *lpNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION ProcBasicInfo;
	
	ProcBasicInfo.PebBaseAddress = (_PEB*)0x7ffdf000;
	
	HMODULE hLibrary;
	hLibrary = GetModuleHandle("ntdll.dll");
	lpNtQueryInformationProcess = (NTQUERYINFO *) GetProcAddress(hLibrary,"NtQueryInformationProcess");
	DWORD buffer;

	(*lpNtQueryInformationProcess)(hProc,ProcessBasicInformation,&ProcBasicInfo,sizeof(ProcBasicInfo),&buffer);
	


struct __PEB
{
    DWORD   dwFiller[4];
    DWORD   dwInfoBlockAddress;
} PEB;

	ReadProcessMemory(hProc,ProcBasicInfo.PebBaseAddress,
		&PEB,sizeof(PEB),&buffer);
	struct __INFOBLOCK
{
    DWORD   dwFiller[16];
    WORD    wLength;
    WORD    wMaxLength;
    DWORD   dwCmdLineAddress;
} Block;
	ReadProcessMemory(hProc, (LPVOID) PEB.dwInfoBlockAddress, 
                             &Block, sizeof(Block), &buffer);
	TCHAR *pszCmdLine = new TCHAR[Block.wMaxLength];
	ReadProcessMemory(hProc,(LPVOID)Block.dwCmdLineAddress,pszCmdLine,Block.wMaxLength,&buffer);

	return 0;

}



int main() {
	
	DWORD pid;
	cout << "usage: pid: ";	
	cin >> pid;

	get_done(pid);
	cin.get();
}