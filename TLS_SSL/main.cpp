#include <Windows.h>
#include "client.h"
#include "server.h"
#include <stdio.h>
#include "iocpserver.h"
#include "main.h"

int main(int argc, char** argv) {
    //CloseHandle(CreateThread(0,0, (LPTHREAD_START_ROUTINE) sslServer,0,0,0));

    CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)IocpServerEntry, 0, 0, 0));

    Sleep(2000);
    sslClient(TEST_IP, 4433);

    getchar();
    return 0;
}