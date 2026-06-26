


#include <winsock2.h>
#include <iostream>
#include <windows.h>
#include <process.h>
using namespace std;

#pragma comment (lib,"ws2_32.lib")



typedef struct _PerHandle
{
    SOCKET m_sock;
    sockaddr_in m_addr;
}PerHandle, * PtrPerHandle;

typedef struct _PerIO
{
    OVERLAPPED m_overlapped;
    char buf[512];
    int m_operationType;

#define OP_READ 1
#define OP_WRITE 2
#define OP_ACCEPT 3
}PerIO, * PtrPerIO;



UINT WINAPI ServerThread(PVOID pvParam);


void mytest() {
    DWORD array[100] = { 0 };
    printf("first value:%x\r\nsecond value:%x\r\n", array + 5, array[5]);
    return;
}

int iocp_test()
{
    mytest();

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "failed to load winsock !" << endl;
        exit(0);
    }
    // 创建完成端口对象       
    HANDLE hCompletion = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);

    /*创建服务线程，构建服务线程池*/
    _beginthreadex(NULL, 0, ServerThread, (LPVOID)hCompletion, 0, 0);

    /*创建监听套接字，并监听连接*/
    SOCKET myListen = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = ntohs(5500);
    localAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    localAddr.sin_addr.S_un.S_addr = INADDR_ANY;
    bind(myListen, (sockaddr*)&localAddr, sizeof(localAddr));
    listen(myListen, 16);
    cout << "server is listening......" << endl;

    /*接受客户端的连接，并将读写操作投放到重叠IO中*/
    while (true)
    {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET newClient = accept(myListen, (sockaddr*)&clientAddr, &clientAddrLen);
        /*将套接字与完成端口关联*/

        PtrPerHandle ptrPerHandle = new PerHandle();
        ptrPerHandle->m_sock = newClient;
        ptrPerHandle->m_addr = clientAddr;
        CreateIoCompletionPort((HANDLE)ptrPerHandle->m_sock, hCompletion, (ULONG_PTR)ptrPerHandle, 0);
        /*投放异步重叠IO*/
        PtrPerIO ptrPerIO = new PerIO();
        ptrPerIO->m_operationType = OP_READ;
        WSABUF buf;
        buf.buf = ptrPerIO->buf;
        buf.len = 512;
        DWORD dwRecv;
        DWORD dwFlag = 0;
        ::WSARecv(ptrPerHandle->m_sock, &buf, 1, &dwRecv, &dwFlag, &ptrPerIO->m_overlapped, NULL);
    }
}





UINT WINAPI ServerThread(PVOID pvParam)
{
    HANDLE hCompletion = (HANDLE)pvParam;
    DWORD dwTrans;
    PtrPerHandle ptrPerHandle;
    PtrPerIO ptrPerIO;
    while (true)
    {
        /*阻塞线程直到有IO操作完成，并通过参数返回操作结果。*/
        BOOL ret = ::GetQueuedCompletionStatus(hCompletion, &dwTrans, (PULONG_PTR)&ptrPerHandle,
            (LPOVERLAPPED*)&ptrPerIO, WSA_INFINITE);

        if (!ret)
        {
            closesocket(ptrPerHandle->m_sock);

            delete(ptrPerHandle);
            delete(ptrPerIO);
            continue;
        }
        /*读或写数据为空*/
        if (dwTrans == 0 && (ptrPerIO->m_operationType == OP_READ || ptrPerIO->m_operationType == OP_WRITE))
        {
            closesocket(ptrPerHandle->m_sock);
            delete(ptrPerHandle);
            delete(ptrPerIO);
            continue;
        }
        switch (ptrPerIO->m_operationType)
        {
        case OP_READ:
        {
            ptrPerIO->buf[dwTrans] = '\0';
            cout << ptrPerIO->buf << endl;
            WSABUF buf;
            buf.buf = ptrPerIO->buf;
            buf.len = 512;
            DWORD dwRecv;
            DWORD dwFlag = 0;
            ::WSARecv(ptrPerHandle->m_sock, &buf, 1, &dwRecv, &dwFlag, &ptrPerIO->m_overlapped, NULL);
        }
        break;
        case OP_WRITE:
        case OP_ACCEPT:
            break;
        }
    }
    return 0;
}
