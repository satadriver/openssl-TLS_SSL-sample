#include <Windows.h>
#include "client.h"
#include "server.h"


int main(int argc, char** argv) {
    CloseHandle(CreateThread(0,0, (LPTHREAD_START_ROUTINE)   sslServer,0,0,0));

    Sleep(1000);
    sslClient("127.0.0.1", 4433);

    return 0;
}