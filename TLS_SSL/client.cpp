

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#pragma warning(disable:4996)

void sslClient(const char * host,int port)
{
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    const SSL_METHOD* client_method;
    X509* server_cert;
    int sd, err;
    char* str, * hostname, outbuf[4096], inbuf[4096], host_header[512];
    struct hostent* host_entry;
    struct sockaddr_in server_socket_address;
    struct in_addr ip;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return ;
    }

    /* (1) 初始化openssl库 */
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    client_method = SSLv23_client_method();
    ctx = SSL_CTX_new(client_method);
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed:\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("(1) SSL context initialized\n\n");

    /* (2) 把域名转换成ip地址 */
    hostname = (char*)host;
    host_entry = gethostbyname(hostname);
    memcpy(&(ip.s_addr), host_entry->h_addr, host_entry->h_length);
    //memcpy(host_entry->h_addr, &(ip.s_addr), host_entry->h_length);
    printf("(2) '%s' has IP address '%s'\n\n", hostname, inet_ntoa(ip));

    /* (3) 用tcp连接到server的443端口 */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_socket_address, '\0', sizeof(server_socket_address));
    server_socket_address.sin_family = AF_INET;
    server_socket_address.sin_port = htons(port);
    memcpy(&(server_socket_address.sin_addr.s_addr),host_entry->h_addr, host_entry->h_length);
    //server_socket_address.sin_addr.s_addr = inet_addr(host);
    err = connect(sd, (struct sockaddr*)&server_socket_address, sizeof(server_socket_address));
    if (err < 0) 
    { 
        perror("can't connect to server port"); 
        exit(1); 
    }
    printf("(3) TCP connection open to host '%s', port %d\n\n",
        hostname, ntohs(server_socket_address.sin_port));

    /* (4) 在tcp连接上进行ssl握手 */
    ssl = SSL_new(ctx); /* 创建ssl句柄 ，之后的send，recv都在ssl句柄上进行 */
    if (!ssl) {
        fprintf(stderr, "SSL_new failed:\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    SSL_set_fd(ssl, sd); /* 把ssl句柄绑定到scoket */
    err = SSL_connect(ssl); /* 启动ssl握手 */
    printf("(4) SSL endpoint created & handshake completed\n\n");

    /* (5) 打印出协商的好的加密密文 */
    printf("(5) SSL connected with cipher: %s\n\n", SSL_get_cipher(ssl));

    /* (6) 打印服务器的证书  */
    //server_cert = SSL_get_peer_certificate(ssl);
    //printf("(6) server's certificate was received:\n\n");
    //str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    //printf("  subject: %s\n", str);
    //str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    //printf("  issuer: %s\n\n", str);
    /* 这里对证书进行验证 */
    //X509_free(server_cert);

    /* (7) 握手完成 --- 开始在ssl上发送http请求 */
    sprintf(host_header, "Host: %s:%d\r\n", hostname,port);
    strcpy(outbuf, "GET / HTTP/1.0\r\n");
    strcat(outbuf, host_header);
    strcat(outbuf, "Connection: close\r\n");
    strcat(outbuf, "\r\n");
    err = SSL_write(ssl, outbuf,(int) strlen(outbuf));
    //shutdown(sd, 1); /* send EOF to server */
    printf("(7) sent HTTP request over encrypted channel:\n\n%s\n", outbuf);


    /* (8) 通过ssl句柄读取服务器响应 */
    
    int recvlen = SSL_read(ssl, inbuf, 1);
    recvlen += SSL_read(ssl, inbuf+1, sizeof(inbuf) - 2);
    printf("(8) got back %d bytes of HTTP response:\n", recvlen);
    //do {
    //    memset(inbuf, 0, sizeof(inbuf));
    //    err = SSL_read(ssl, inbuf, sizeof(inbuf) - 1);
    //    printf("%s", inbuf);
    //    inbuf[err] = '\0';
    //} while (err > 0);
    /* (9) 释放连接，句柄 */
    SSL_shutdown(ssl);
    closesocket(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("(9) all done, cleaned up and closed connection\n\n");
}