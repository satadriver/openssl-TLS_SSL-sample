#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "main.h"

#include <vector>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <queue>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#ifndef TEST_IP

#endif

// ---------- 发送缓冲区节点 ----------
struct SendBuf {
    WSABUF wsabuf;
    OVERLAPPED ov;
    char* data;
    SendBuf(const char* d, size_t len) {
        data = new char[len];
        memcpy(data, d, len);
        wsabuf.buf = data;
        wsabuf.len = (ULONG)len;
        memset(&ov, 0, sizeof(OVERLAPPED));
    }
    ~SendBuf() { delete[] data; }
};

// ---------- 每个连接的状态 ----------
struct PerConnection {
    SOCKET sock = INVALID_SOCKET;
    SSL* ssl = nullptr;
    BIO* bioIn = nullptr;
    BIO* bioOut = nullptr;

    OVERLAPPED ovRecv;
    WSABUF wsabuf;
    char recvBuf[8192];
    DWORD recvBytes = 0;
    DWORD flags = 0;

    std::queue<SendBuf*> sendQueue;   // 发送队列
    bool isSending = false;           // 标记是否正在异步发送

    PerConnection() {
        memset(&ovRecv, 0, sizeof(OVERLAPPED));
    }
    ~PerConnection() {
        while (!sendQueue.empty()) {
            delete sendQueue.front();
            sendQueue.pop();
        }
    }
};

// ---------- 全局变量 ----------
HANDLE g_iocp = NULL;
SSL_CTX* g_sslCtx = NULL;
std::atomic<bool> g_running(true);
std::vector<std::thread> g_workerThreads;

// ---------- 日志宏 ----------
#define LOG(fmt, ...) printf("[%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

// ---------- 初始化 OpenSSL ----------
bool InitSSL() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    g_sslCtx = SSL_CTX_new(TLS_server_method());
    if (!g_sslCtx) {
        LOG("SSL_CTX_new failed");
        return false;
    }

    SSL_CTX_set_security_level(g_sslCtx, 0);
    SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_NONE, 0);

    if (SSL_CTX_use_certificate_file(g_sslCtx, "demo_tls_cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(g_sslCtx, "demo_tls_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (SSL_CTX_check_private_key(g_sslCtx) != 1) {
        LOG("Private key does not match certificate");
        return false;
    }
    LOG("OpenSSL initialized successfully");
    return true;
}

// ---------- 创建连接对象 ----------
PerConnection* CreateSSLConnection(SOCKET sock) {
    auto* conn = new PerConnection();
    conn->sock = sock;

    conn->ssl = SSL_new(g_sslCtx);
    conn->bioIn = BIO_new(BIO_s_mem());
    conn->bioOut = BIO_new(BIO_s_mem());
    SSL_set_bio(conn->ssl, conn->bioIn, conn->bioOut);
    SSL_set_accept_state(conn->ssl);

    // 设置为非阻塞（建议）
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    return conn;
}

// ---------- 异步发送函数（将数据加入队列并投递） ----------
void PostSend(PerConnection* conn) {
    if (conn->isSending || conn->sendQueue.empty()) return;

    SendBuf* sb = conn->sendQueue.front();
    conn->isSending = true;
    DWORD sent = 0;
    int ret = WSASend(conn->sock, &sb->wsabuf, 1, &sent, 0, &sb->ov, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG("WSASend failed: %d", WSAGetLastError());
        conn->isSending = false;
        // 关闭连接等处理由上层完成
    }
}

// ---------- 发送应用数据（明文） ----------
void SendApplicationData(PerConnection* conn, const char* plaintext, size_t len) {
    int written = SSL_write(conn->ssl, plaintext, (int)len);
    if (written > 0) {
        // 从 bioOut 中读取加密数据并放入发送队列
        char outBuf[8192];
        int outLen;
        while ((outLen = BIO_read(conn->bioOut, outBuf, sizeof(outBuf))) > 0) {
            SendBuf* sb = new SendBuf(outBuf, outLen);
            conn->sendQueue.push(sb);
        }
        PostSend(conn); // 尝试发送
    }
    else {
        int err = SSL_get_error(conn->ssl, written);
        LOG("SSL_write error: %d", err);
    }
}

// ---------- 核心接收处理（单次调用，不循环） ----------
void OnRecv(PerConnection* conn, char* data, size_t len) {
    DWORD flags = 0;
    int ret = 0;
    char plaintext[4096];
    int bytesRead = 0;
    if (!conn || !data || len == 0) return;

    // 1. 将密文写入 bioIn
    int written = BIO_write(conn->bioIn, data, (int)len);
    if (written <= 0) {
        LOG("BIO_write failed");
        goto error;
    }

    // 2. 尝试读取解密后的应用数据（会自动触发握手）
    
    bytesRead = SSL_read(conn->ssl, plaintext, sizeof(plaintext) - 1);
    if (bytesRead > 0) {
        plaintext[bytesRead] = '\0';
        LOG("Received: %s", plaintext);
        // 可在此处理应用层数据，例如回显
        SendApplicationData(conn, "ACK", 3);
    }
    else {
        int err = SSL_get_error(conn->ssl, bytesRead);
        if (err == SSL_ERROR_WANT_READ) {
            // 需要更多数据，正常，继续接收
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            // 需要发送数据，让 SSL 输出 bioOut
            // 发送所有 bioOut 中的数据
        }
        else if (err == SSL_ERROR_ZERO_RETURN) {
            LOG("SSL shutdown received");
            goto error;
        }
        else {
            LOG("SSL_read error: %d", err);
            goto error;
        }
    }

    // 3. 将从 bioOut 中读取所有待发送密文并加入队列
    char outBuf[8192];
    int outLen;
    while ((outLen = BIO_read(conn->bioOut, outBuf, sizeof(outBuf))) > 0) {
        SendBuf* sb = new SendBuf(outBuf, outLen);
        conn->sendQueue.push(sb);
    }
    PostSend(conn);  // 尝试异步发送

    // 4. 继续投递下一次接收
    conn->wsabuf.buf = conn->recvBuf;
    conn->wsabuf.len = sizeof(conn->recvBuf);

    ret = WSARecv(conn->sock, &conn->wsabuf, 1, &conn->recvBytes, &flags, &conn->ovRecv, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        LOG("WSARecv failed: %d", WSAGetLastError());
        goto error;
    }
    return;

error:
    closesocket(conn->sock);
    delete conn;
}

// ---------- 工作线程 ----------
DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HANDLE iocp = (HANDLE)lpParam;
    DWORD bytesTransferred = 0;
    ULONG_PTR completionKey = 0;
    LPOVERLAPPED overlapped = NULL;

    while (g_running) {
        BOOL ok = GetQueuedCompletionStatus(iocp, &bytesTransferred, &completionKey, &overlapped, INFINITE);
        if (!ok || !overlapped) {
            if (GetLastError() != WAIT_TIMEOUT) {
                LOG("GetQueuedCompletionStatus error: %d", GetLastError());
            }
            continue;
        }

        PerConnection* conn = (PerConnection*)completionKey;
        if (!conn) continue;

        // 判断完成类型：接收完成 or 发送完成
        if (overlapped == &conn->ovRecv) {
            if (bytesTransferred > 0) {
                OnRecv(conn, conn->recvBuf, bytesTransferred);
            }
            else {
                // 对方关闭或错误
                closesocket(conn->sock);
                delete conn;
            }
        }
        else {
            // 发送完成：从队列中弹出已完成的 SendBuf 并释放
            if (!conn->sendQueue.empty()) {
                SendBuf* sb = conn->sendQueue.front();
                if (&sb->ov == overlapped) {
                    conn->sendQueue.pop();
                    delete sb;
                    conn->isSending = false;
                    // 继续发送队列中剩余数据
                    PostSend(conn);
                }
            }
        }
    }
    return 0;
}

// ---------- 主启动函数 ----------
bool RunSSLServer(const char* ip, int port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

    if (!InitSSL()) {
        WSACleanup();
        return false;
    }

    g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!g_iocp) {
        WSACleanup();
        return false;
    }

    SOCKET listenSock = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (listenSock == INVALID_SOCKET) {
        CloseHandle(g_iocp);
        WSACleanup();
        return false;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listenSock);
        CloseHandle(g_iocp);
        WSACleanup();
        return false;
    }
    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSock);
        CloseHandle(g_iocp);
        WSACleanup();
        return false;
    }
    CreateIoCompletionPort((HANDLE)listenSock, g_iocp, 0, 0);

    int threadCount = std::thread::hardware_concurrency() * 2;
    for (int i = 0; i < threadCount; ++i) {
        std::thread t(WorkerThread, g_iocp);
        t.detach();
    }
    LOG("Server listening on %s:%d", ip, port);

    while (g_running) {
        SOCKET client = accept(listenSock, NULL, NULL);
        if (client == INVALID_SOCKET) continue;

        PerConnection* conn = CreateSSLConnection(client);
        if (!conn) {
            closesocket(client);
            continue;
        }
        CreateIoCompletionPort((HANDLE)client, g_iocp, (ULONG_PTR)conn, 0);

        // 投递首次接收
        conn->wsabuf.buf = conn->recvBuf;
        conn->wsabuf.len = sizeof(conn->recvBuf);
        DWORD flags = 0;
        int ret = WSARecv(client, &conn->wsabuf, 1, &conn->recvBytes, &flags, &conn->ovRecv, NULL);
        if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            closesocket(client);
            delete conn;
        }
    }

    closesocket(listenSock);
    return true;
}

// ---------- 入口函数 ----------
int __stdcall IocpServerEntry() {
    char path[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path);
    printf("Current directory: %s\n", path);
    if (RunSSLServer(TEST_IP, 4433)) {
        printf("Server is running on %s:4433 ... Press Enter to stop.\n", TEST_IP);
        getchar();
        g_running = false;
        Sleep(1000);
        return 0;
    }
    else {
        printf("Server start failed.\n");
        return 1;
    }
}