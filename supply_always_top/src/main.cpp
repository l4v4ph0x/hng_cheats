/*
* Copyright (C) 2018  lava
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#define size_to_scan 786

unsigned long get_proc(const char *name) {
    void *snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(snapshot, &pe32))
        if (strcmp(pe32.szExeFile, name) == 0)
            return pe32.th32ProcessID;

    return 0;
}

unsigned long get_module(unsigned long pid, const char *module_name, unsigned long *size) {
    void *snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    while (Module32Next(snapshot, &me32)) {
        if (strcmp(me32.szModule, module_name) == 0) {
            printf("\n\tmodule: %s, %08X ", me32.szModule, me32.modBaseAddr);
            if (size != 0) *size = me32.modBaseSize;
            return (unsigned long)me32.modBaseAddr;
        }
    } return 0;
}


unsigned long search(void *handle, unsigned long start, unsigned long size, const char *bytesToSearch, unsigned long sizeToSearch, unsigned long step) {
    unsigned char bytes[size_to_scan];
    unsigned long gotCount = 0;

    for (unsigned long i = 0; i < size; i += size_to_scan) {
        ReadProcessMemory(handle, (PVOID)(start + i), &bytes, size_to_scan, 0);
        for (unsigned short j = 0; j < size_to_scan; j++) {
            bool failed = false;

            for (unsigned char k = 0; k < sizeToSearch; k++) {
                if (*(unsigned char *)((unsigned long)&bytes + j + k) != (unsigned char)bytesToSearch[k]) {
                    failed = true;
                    break;
                }
            }

            if (failed == false) {
                gotCount++;
                if (gotCount == step)
                    return start + i + j;
            }
        }
    } return 0;
}


int main() {
    // vars this func uses
    unsigned long pid; // process id
    unsigned long player_dll;
    unsigned long player_dll_size;
    void *handle;

    unsigned long oldProtect;
    unsigned long addr;
    bool enabling_cheat;


    // declare vars
    pid = 0;
    player_dll = 0;
    player_dll_size = 0x7FFFFFFF;

    oldProtect = 0;
    addr = 0;
    enabling_cheat = false;

    printf("||=======================================================||\n");
    printf("||          cheat for hng version 142953 QQ              ||\n");
    printf("||             show always supply boxes                  ||\n");
    printf("|| made by: lava                                         ||\n");
    printf("||=======================================================||\n");

    for (; get_proc("HeroesAndGeneralsDesktop.exe") != 0; ) {
        printf("searching for hng ... ");
        for (pid = 0; pid == 0; ) pid = get_proc("hng.exe");
        printf("| Done\n");

        printf("hook to hng ... ");
        handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pid);
        if (handle) {
            printf("searching modules ... ");
            for (; player_dll == 0; Sleep(1000)) player_dll = get_module(pid, "player.dll", &player_dll_size);
            printf("<<-- Done\n");

            printf("searching for where tu put new code ... ");

            // for meds
            addr = search(handle, player_dll, player_dll_size, "\xF6\x45\xEC\x01\x0F\x84", 6, 1);
            if (addr != 0) {
                VirtualProtectEx(handle, (void *)(addr), 10, PAGE_EXECUTE_READWRITE, (LPDWORD)&oldProtect);
                enabling_cheat = WriteProcessMemory(handle, (void *)(addr), "\xC7\x45\xEC\x0D\x0A\x00\x00\x90\x90\x90", 10, 0);
                VirtualProtectEx(handle, (void *)(addr), 10, oldProtect, NULL);
            } else {
                printf("| failed\n");
                printf("error log: already applied or cheat is out of date ... ");
                enabling_cheat = true;
            }

            // for ammo
            addr = search(handle, player_dll, player_dll_size, "\xF6\x45\xEC\x01\x0F\x84", 6, 1);
            if (addr != 0) {
                VirtualProtectEx(handle, (void *)(addr), 10, PAGE_EXECUTE_READWRITE, (LPDWORD)&oldProtect);
                enabling_cheat = WriteProcessMemory(handle, (void *)(addr), "\xC7\x45\xEC\x0D\x0A\x00\x00\x90\x90\x90", 10, 0);
                VirtualProtectEx(handle, (void *)(addr), 10, oldProtect, NULL);
            }

            

            if (enabling_cheat) {
                printf("| Done\n");

                printf("waiting for end game ... ");
                for (;; Sleep(500)) {
                    // check if process is closed
                    if (get_proc("hng.exe") != 0) {
                        // proccess is still alive
                    } else {
                        printf("end of game listening new\n");
                        break;
                    }
                }
            } else {
                printf("| failed\n");
                printf("error log: try again or ur out of luck\n");
            }
        } else {
            printf("| Failed\n");
            printf("error log: run cheat with admin rights\n");
        }
    }

    printf("bye bye\n");
    Sleep(1000);
    printf(".");
    Sleep(1000);
    printf(".");
    Sleep(1000);
    printf(".\n");
    Sleep(1000);

    return 0;
}
