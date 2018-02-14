/*
* Copyright (C) 2017  lava
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

const unsigned long OFFSET_TERMINAL = 0x5BFE0;
const unsigned long OFFSET_SHOW_PROJECTILES = 0x10C;
const unsigned long OFFSET_CLEAR_ALL_DEBUG = 0x378;

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


int main() {
    // vars this func uses
    unsigned long pid; // process id
    unsigned long globals_dll;
    unsigned long terminal;
    void *handle;

    bool enabling_cheat;


    // declare vars
    pid = 0;
    globals_dll = 0;
    terminal = 0;

    enabling_cheat = false;

    printf("||=======================================================||\n");
    printf("||          cheat for hng version 140116 PP              ||\n");
    printf("||                 show projectiles                      ||\n");
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
            for (; globals_dll == 0; Sleep(1000)) globals_dll = get_module(pid, "globals.dll", 0);
            printf("<<-- Done\n");

            printf("enabling show projectile path ... ");
            enabling_cheat = ReadProcessMemory(handle, (void *)(globals_dll + OFFSET_TERMINAL), &terminal, 4, 0);
            enabling_cheat = WriteProcessMemory(handle, (void *)(terminal + OFFSET_SHOW_PROJECTILES), "\x01", 1, 0);

            if (enabling_cheat) {
                printf("| Done\n");

                printf("wokring on it ... ");
                for (;; Sleep(400)) {
                    // check if process is closed
                    if (get_proc("hng.exe") != 0) {
                        WriteProcessMemory(handle, (void *)(terminal + OFFSET_CLEAR_ALL_DEBUG), "\x01", 1, 0);
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