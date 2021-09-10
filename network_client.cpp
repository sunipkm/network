/**
 * @file network_client.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.09.02
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "network_common.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <new>

#ifndef NETWORK_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <time.h>
#include <assert.h>
#include "meb_debug.hpp"
#ifdef __linux__
#include <signal.h>
#endif
#include "network_client.hpp"

static int ssl_lib_init = 0;

int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s)
#ifndef NETWORK_WINDOWS
{
    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    // Set non-blocking.
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg |= O_NONBLOCK;
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_SETFL)");
        erprintlf(errno);
        return -1;
    }

    // Trying to connect with timeout.
    res = connect(socket, address, socket_size);
    if (res < 0)
    {
        if (errno == EINPROGRESS)
        {
            dbprintlf(YELLOW_FG "EINPROGRESS in connect() - selecting");
            do
            {
                if (tout_s > 1)
                {
                    tv.tv_sec = tout_s;
                }
                else
                {
                    tv.tv_sec = 1; // Minimum 1 second.
                }
                tv.tv_usec = 0;
                FD_ZERO(&myset);
                FD_SET(socket, &myset);
                res = select(socket + 1, NULL, &myset, NULL, &tv);
                if (res < 0 && errno != EINTR)
                {
                    dbprintlf(RED_FG "Error connecting.");
                    erprintlf(errno);
                    return -1;
                }
                else if (res > 0)
                {
                    // Socket selected for write.
                    lon = sizeof(int);
                    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
                    {
                        dbprintlf(RED_FG "Error in getsockopt()");
                        erprintlf(errno);
                        return -1;
                    }

                    // Check the value returned...
                    if (valopt)
                    {
                        dbprintlf(RED_FG "Error in delayed connection()");
                        erprintlf(valopt);
                        return -1;
                    }
                    break;
                }
                else
                {
                    dbprintlf(RED_FG "Timeout in select(), cancelling!");
                    return -1;
                }
            } while (1);
        }
        else
        {
            fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
            dbprintlf(RED_FG "Error connecting.");
            erprintlf(errno);
            return -1;
        }
    }
    // Set to blocking mode again...
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg &= (~O_NONBLOCK);
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    return socket;
}
#else
{
    int res = connect(socket, address, socket_size);
    if (res)
        return -1;
    return 1;
}
#endif

void InitializeSSLLibrary()
{
    if (ssl_lib_init++ == 0)
    {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
#ifdef __linux__
        signal(SIGPIPE, SIG_IGN);
#endif
#ifdef NETWORK_WINDOWS
        WSADATA wsaData;
        int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (ret != 0)
        {
            dbprintlf(FATAL "WSAStartup failed with error: %d", ret);
        }
#endif
    }
}

SSL_CTX *InitializeSSLClient(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL)
    {
        dbprintlf(FATAL "Could create SSL context");
    }
    else
    {
        SSL_CTX_set_dh_auto(ctx, 1);
    }
    return ctx;
}

void DestroySSL()
{
    if (--ssl_lib_init == 0)
    {
        ERR_free_strings();
        EVP_cleanup();
#ifdef NETWORK_WINDOWS
        WSACleanup();
#endif
    }
}

int NetDataClient::OpenSSLConn()
{
    if (ctx != NULL && connection_ready)
    {
        cssl = SSL_new(ctx);
        if (!SSL_set_fd(cssl, _socket))
        {
            dbprintlf("Could not open SSL connection");
            return -1;
        }
        int ssl_err = SSL_connect(cssl);
        if (ssl_err <= 0)
        {
            dbprintlf("SSL error %d, %d", ssl_err, SSL_get_error(cssl, ssl_err));
            CloseSSLConn();
            return -1;
        }
        ssl_ready = true;
        return 1;
    }
    return -1;
}

NetDataClient::~NetDataClient()
{
    Close();
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    ctx = NULL;
    DestroySSL();
    if (auth_token != nullptr)
        delete auth_token;
    auth_token = nullptr;
}

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, sha1_hash_t *auth, int polling_rate, ClientClass dclass, ClientID did)
    : NetData()
{
    ctx = InitializeSSLClient();
    if (ip_addr == NULL)
        strcpy(this->ip_addr, "127.0.0.1");
    else
    {
        strncpy(this->ip_addr, ip_addr, sizeof(this->ip_addr));
    }
    if (auth == NULL || auth == nullptr)
    {
        dbprintlf(FATAL "Authentication token not provided, exiting");
        throw std::invalid_argument("Auth is NULL");
    }
    if (auth->hash() == 0x0)
    {
        dbprintlf(FATAL "Authentication hash invalid!");
        throw std::invalid_argument("Auth is uninitialized");
    }
    if (auth_token == nullptr)
        auth_token = new sha1_hash_t();
    auth_token->copy(auth->bytes);
    this->polling_rate = polling_rate;
    strcpy(disconnect_reason, "N/A");
    memset(server_ip, 0x0, sizeof(struct sockaddr_in));
    server_ip->sin_family = AF_INET;
    server_ip->sin_port = htons((int)server_port);
    devclass = dclass;
    devId = did;
    origin = ((uint32_t)dclass << 8) | ((uint32_t)did);
};

int NetDataClient::ConnectToServer()
{
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s.", ip_addr);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    _socket = socket(AF_INET, SOCK_STREAM, 0);
    if (_socket < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, ip_addr, &server_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(_socket, (struct sockaddr *)server_ip, sizeof(server_ip), 1) < 0)
    {
        dbprintlf(FATAL "Connection failure.");
        connect_status = -3;
    }
    else
    {
        connect_status = 1;
        connection_ready = true;
        dbprintlf(GREEN_FG "Set connection ready");
    }
    if (connect_status < 0)
    {
        Close();
        return -200;
    }
    // If the socket is closed, but recv(...) was already called, it will be stuck trying to receive forever from a socket that is no longer active. One way to fix this is to close the RX thread and restart it. Alternatively, we could implement a recv(...) timeout, ensuring a fresh socket value is used.
    // Here, we implement a recv(...) timeout.
    struct timeval timeout;
    timeout.tv_sec = RECV_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout); // connection timeout set
    int set = 1;
#if !defined(__linux__)
#if !defined(NETWORK_WINDOWS)
    setsockopt(_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
#endif
    int retval;
    NetVertex server_v = 0;
    NetFrame *frame;
    // Step 1. Receive server ping
    // frame = new NetFrame();
    // for (int i = 0; (i < 20) && (frame->recvFrame(this) < 0); i++)
    //     ;
    // if (frame->getType() != NetType::POLL)
    // {
    //     dbprintlf("Did not receive a poll packet, received %d", frame->getType());
    //     Close();
    //     delete frame;
    //     return -2;
    // }
    // server_v = frame->getOrigin();
    // dbprintlf("Server Origin: 0x%x", server_v);
    // delete frame;
    // Step 2. Connect SSL
    if ((retval = OpenSSLConn()) > 0)
    {
        dbprintlf("Connected to %s over SSL", ip_addr);
    }
    else
    {
        dbprintlf("SSL connect failed: %d", retval);
        Close();
        return -3;
    }
    // Step 3. Send Auth Token
    frame = new NetFrame(auth_token->bytes, SHA512_DIGEST_LENGTH, 0, NetType::AUTH, FrameStatus::ACK, server_v);
    usleep(20000);
    if (frame->sendFrame(this) <= 0)
    {
        delete frame;
        dbprintlf("Could not send auth token, exiting");
        Close();
        return -4;
    }
    delete frame;
    // Step 4. Retrieve assigned vertex
    frame = new NetFrame();
    for (int i = 0; (i < 20) && (frame->recvFrame(this, i == 19) < 0); i++)
    {
        usleep(20000);
    }
    if (frame->getType() != NetType::SRV)
    {
        dbprintlf("Expecting %d, got %d for frame type", NetType::SRV, frame->getType());
        Close();
        delete frame;
        return -5;
    }
    else if (frame->getPayloadSize() != 2 * sizeof(NetVertex))
    {
        dbprintlf("Expecting package size %lu, got %u (2x NetVertex)", 2 * sizeof(NetVertex), frame->getPayloadSize());
        Close();
        delete frame;
        return -6;
    }
    NetVertex vertices[2];
    frame->retrievePayload(vertices, sizeof(vertices));
    origin = vertices[0];
    server_vertex = vertices[1];
    delete frame;
    // Step 5. Send ACK
    frame = new NetFrame(&origin, sizeof(NetVertex), 0, NetType::SRV, FrameStatus::ACK, server_vertex);
    if (frame->sendFrame(this) <= 0)
    {
        dbprintlf("Failed to send ACK to server, server closed connection");
        delete frame;
        Close();
        return -7;
    }
    recv_active = true;
    return connect_status;
}

#ifndef NETWORK_WINDOWS
void *gs_polling_thread(void *args)
#else
DWORD WINAPI gs_polling_thread(LPVOID args)
#endif
{
    dbprintlf(BLUE_FG "Beginning polling thread.");
    NetDataClient *network_data = (NetDataClient *)args;
#ifndef NETWORK_WINDOWS
    sleep(1);
#else
    Sleep(1000);
#endif
    network_data->recv_active = true;
    while (network_data->recv_active)
    {
        if (network_data->connection_ready)
        {
            NetFrame *polling_frame = new NetFrame(NULL, 0, 0, NetType::POLL, FrameStatus::NONE, network_data->server_vertex);
            polling_frame->sendFrame(network_data);
            polling_frame->print();
            delete polling_frame;
        }
        else
        {
            dbprintlf("Connect to server from poll\n");
            network_data->ConnectToServer();
        }
        if (network_data->polling_rate < 1000)
            network_data->polling_rate = 1000; // minimum 1 ms
#ifndef NETWORK_WINDOWS
        usleep(network_data->polling_rate * 1000);
#else
        Sleep(network_data->polling_rate);
#endif
    }
    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
#ifndef NETWORK_WINDOWS
        return nullptr;
#else
        return 0;
#endif
}