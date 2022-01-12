/**
 * @file network_server.cpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Network Server Implementation
 * @version 0.1
 * @date 2021-09-10
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
#include <time.h>
#include <assert.h>
#ifndef NETWORK_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include "meb_debug.hpp"
#ifdef __linux__
#include <signal.h>
#endif

#include "network_server.hpp"

static int ssl_lib_init = 0;

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

SSL_CTX *InitializeSSLServer(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (ctx == NULL)
    {
        dbprintlf(FATAL "Could create SSL context");
        return NULL;
    }
    int use_cert = SSL_CTX_use_certificate_file(ctx, "./cert.pem", SSL_FILETYPE_PEM);
    int use_prv = SSL_CTX_use_PrivateKey_file(ctx, "./key.pem", SSL_FILETYPE_PEM);
    if ((use_cert != 1) || (use_prv != 1) || (SSL_CTX_check_private_key(ctx) != 1))
    {
        dbprintlf("Cert: %d, Private Key: %d, Validation: %d", use_cert, use_prv, SSL_CTX_check_private_key(ctx));
        return NULL;
    }
    SSL_CTX_set_dh_auto(ctx, 1);
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

NetClient::~NetClient()
{
    Close();
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    ctx = NULL;
    DestroySSL();
}

#ifndef NETWORK_WINDOWS
void *gs_accept_thread(void *args)
#else
DWORD WINAPI gs_accept_thread(LPVOID args)
#endif
{
    NetDataServer *serv = (NetDataServer *)args;
    while (!serv->listen_done)
    {
        for (int i = 0; i < serv->num_clients; i++)
        {
            gs_accept(serv, i);
        }
#ifdef NETWORK_WINDOWS
        Sleep(1000);
#else
        sleep(1);
#endif
    }
    return NULL;
}

NetDataServer::NetDataServer(NetPort listening_port, int clients, sha1_hash_t auth_token)
{
    this->auth_token = new sha1_hash_t();
    InitializeSSLLibrary();
    _NetDataServer(listening_port, clients);
    this->auth_token->copy(auth_token.bytes);
}

void NetDataServer::_NetDataServer(NetPort listening_port, int clients)
{
    srand(time(NULL));
    origin = rand() | 0x1000; // ensure byte[1] has MSB set
    if (clients < 1)
        clients = 1;
    else if (clients > 100)
        clients = 100;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 3)
    {
        dbprintlf("Socket creation failed");
        throw std::bad_alloc();
    }
    int opt = 1;
    // Forcefully attaching socket to the port 8080
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   (char *)&opt, sizeof(opt)))
    {
        dbprintlf("setsockopt reuseaddr");
        throw std::invalid_argument("setsockopt reuseaddr");
    }
#ifndef NETWORK_WINDOWS
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                   &opt, sizeof(opt)))
    {
        dbprintlf("setsockopt reuseport");
        throw std::invalid_argument("setsockopt reuseport");
    }
    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags != -1);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

    // Forcefully attaching socket to the port 8080
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(listening_port);

    if (bind(fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        dbprintlf("bind failed");
        throw std::invalid_argument("bind failed");
    }
    if (listen(fd, clients) < 0)
    {
        dbprintlf("listen");
        throw std::invalid_argument("listen");
    }

    this->num_clients = clients;
    this->clients = new NetClient[clients];

    if (this->clients == nullptr)
    {
        dbprintlf("Could not allocate memory for clients");
        throw std::bad_alloc();
    }

    for (int i = 0; i < clients; i++)
    {
        this->clients[i].client_id = i;
        this->clients[i].serv = this;
        this->clients[i].origin = (NetVertex)0;
        for (int j = 20; (j > 0) && (this->clients[i].ctx == NULL); j--)
            this->clients[i].ctx = InitializeSSLServer();
        if (this->clients[i].ctx == NULL)
        {
            dbprintlf(FATAL "Failed to initialize SSL context for client %d", i);
        }
    }
#ifndef NETWORK_WINDOWS
    if (pthread_create(&accept_thread, NULL, gs_accept_thread, this) != 0)
#else
    DWORD threadId = 0;
    accept_thread = CreateThread(NULL, 0, gs_accept_thread, this, 0, &threadId);
    if (accept_thread == INVALID_HANDLE_VALUE)
#endif
    {
        dbprintlf("Could not start accept thread");
    }
};

NetClient *NetDataServer::GetClient(int id)
{
    if ((id >= num_clients) || (id < 0))
    {
        dbprintlf("Invalid client ID %d, max client ID %d", id, num_clients - 1);
        return NULL;
    }
    return &(clients[id]);
}

NetClient *NetDataServer::GetClient(NetVertex v)
{
    NetClient *ret = nullptr;
    for (int i = 0; i < num_clients; i++)
        if (clients[i].origin == v)
            ret = &(clients[i]);
    return ret;
}

NetDataServer::~NetDataServer()
{
#ifndef NETWORK_WINDOWS
    pthread_cancel(accept_thread);
    if (fd > 0)
    {
        close(fd);
        fd = -1;
    }
#else
    DWORD stat = 0;
    TerminateThread(accept_thread, stat);
    if (fd >= 0)
    {
        closesocket(fd);
        fd = -1;
    }
#endif
    if (clients != nullptr)
        delete[] clients;
    clients = nullptr;
    num_clients = 0;

    if (auth_token != nullptr)
        delete auth_token;
    auth_token = nullptr;
}

int gs_accept_ssl(NetClient *);

int gs_accept(NetDataServer *serv, int client_id)
{
    if (client_id >= serv->num_clients)
    {
        dbprintlf("Invalid client ID, max clients %d", serv->num_clients);
        return -1;
    }
    NetClient *client = &(serv->clients[client_id]);
    if (client->connection_ready)
    {
        return client->_socket;
    }
    if (client->_socket <= 0) // not connected
    {
        client->client_addrlen = sizeof(struct sockaddr_in);
        client->_socket = accept(serv->fd, (struct sockaddr *)&(client->client_addr), (socklen_t *)&(client->client_addrlen));
    }
    if (client->_socket <= 0) // connection attempt unsuccessful
        return client->_socket;

    client->conn_attempt = true;
    int set = 1;
#ifndef __linux__
#ifndef NETWORK_WINDOWS
    setsockopt(client->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
#endif
    NetFrame *frame;
    int bytes;
    // Step 1. Poll the client for device class and type
    // frame = new NetFrame(NULL, 0, 0, NetType::POLL, FrameStatus::NONE, 0); // vertex does not matter at this point
    // bytes = frame->sendFrame(client);
    // delete frame;
    // if (bytes <= 0)
    // {
    //     dbprintlf("Could not poll client, closing connection");
    //     client->Close();
    //     return -5;
    // }
    // Step 2. Switch to SSL
    if (gs_accept_ssl(client) > 0) // Set up SSL as server
    {
        dbprintlf("Accepted SSL connection from client %d (%p)", client_id, client);
    }
    else
    {
        dbprintlf("Could not accept SSL connection from client %d (%p)", client_id, client);
        client->Close();
        return -101;
    }
    // Step 3. Wait for Auth Token
    frame = new NetFrame();
    for (int i = 0; (i < 20) && (frame->recvFrame(client, i == 19) < 0); i++)
        usleep(20000);
    if (frame->getPayloadSize() != SHA512_DIGEST_LENGTH) // not valid size for SHA token
    {
        dbprintlf("Expected %d bytes, received %d bytes", SHA512_DIGEST_LENGTH, frame->getPayloadSize());
        client->Close();
        return -102;
    }
    if (frame->getType() != NetType::AUTH) // expecting packet of type auth token
    {
        dbprintlf("Expected type 0x%x, got type 0x%x", NetType::AUTH, frame->getType());
        client->Close();
        return -103;
    }
    sha1_hash_t auth_token;
    frame->retrievePayload(auth_token.bytes, SHA512_DIGEST_LENGTH);
    if (!(serv->auth_token->equal(auth_token)))
    {
        dbprintlf("Authentication token mismatch");
        client->Close();
        return -104;
    }
    // Step 4. Assign vertex or hang up
    NetVertex vertices[2];
    NetVertex _vertex = rand();
    while (_vertex < 0xffff)
    {
#ifdef NETWORK_WINDOWS
        while(rand_s(&_vertex));
#else
        _vertex = rand();
#endif
    }
    _vertex = _vertex & 0xffff0000;
    vertices[0] = (_vertex);
    vertices[0] |= frame->getOrigin() & 0x7fff;
    client->devclass = frame->getOrigin() >> 8;
    client->devId = frame->getOrigin();
    vertices[1] = serv->origin;

    delete frame;

    frame = new NetFrame((void *)vertices, sizeof(vertices), (int)NetType::SRV, NetType::SRV, FrameStatus::NONE, vertices[0]);
    bytes = frame->sendFrame(client);
    delete frame;
    if (bytes <= 0)
    {
        dbprintlf("Cound not send vertex identifiers, closing connection");
        client->Close();
        return -105;
    }
#ifndef NETWORK_WINDOWS
    usleep(20000);
#else
    Sleep(20);
#endif
    // Step 5. Receive ack
    int retval;
    frame = new NetFrame();
    for (int i = 0; i < 20; i++)
    {
        retval = frame->recvFrame(client, i == 19);
        if (retval > 0)
            break;
        usleep(20000);
    }
    if (retval < 0)
    {
        dbprintlf(FATAL "Did not receive acknowledgement: %d", retval);
        client->Close();
        return -106;
    }
    else if (frame->getType() != NetType::SRV)
    {
        dbprintlf(RED_FG "Expecting ACK, received %d", (int)frame->getType());
        client->Close();
        return -107;
    }
    else if (frame->getStatus() != FrameStatus::ACK)
    {
        dbprintlf("Expecting ACK, received %d", (int)frame->getStatus());
        client->Close();
        return -108;
    }
    else if (frame->getPayloadSize() != sizeof(NetVertex))
    {
        dbprintlf("Expecting client to send back updated netvertex");
        client->Close();
        return -109;
    }
    NetVertex vertex;
    frame->retrievePayload(&vertex, sizeof(NetVertex));
    if (vertex != vertices[0])
    {
        dbprintlf("Expecting vertex 0x%x, obtained 0x%x", vertices[0], vertex);
        client->Close();
        return -110;
    }
    // success!
    client->connection_ready = true;
    client->conn_attempt = false;
    return client->_socket;
}

int gs_accept_ssl(NetClient *client)
{
    if (client->server)
    {
        dbprintlf("Function not applicable on a server");
        return -100;
    }
    if (client->cssl != NULL)
    {
        dbprintlf("Connection to client %p already over SSL", client);
        return 1;
    }
    if (client->ctx == NULL)
    {
        dbprintlf(FATAL "SSL context not available for client %d", client->client_id);
        return -1;
    }
    client->cssl = SSL_new(client->ctx);
    if (client->cssl == NULL)
    {
        dbprintlf(FATAL "Could not allocate SSL connection");
        return -2;
    }
    if (SSL_set_fd(client->cssl, client->_socket) == 0)
    {
        dbprintlf("Could not attach C socket to SSL socket");
        client->CloseSSLConn();
        return -3;
    }
    int accept_retval = 0;
    for (int i = 0; i < 1000; i++)
    {
        accept_retval = SSL_accept(client->cssl);
        if (accept_retval == 0)
        {
            break;
        }
        else if (accept_retval == -1)
        {
            int err = SSL_get_error(client->cssl, accept_retval);
            if (err == SSL_ERROR_WANT_READ)
            {
#ifndef NETWORK_WINDOWS
                usleep(10000);
#else
                Sleep(10);
#endif
            }
            else if (err == SSL_ERROR_WANT_WRITE)
            {
#ifndef NETWORK_WINDOWS
                usleep(10000);
#else
                Sleep(10);
#endif
            }
            else if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            {
                dbprintlf("Error syscall / ssl");
                break;
            }
            else if (err == SSL_ERROR_ZERO_RETURN)
            {
                dbprintlf("Error return zero");
                break;
            }
        }
        else
        {
            /* Continue */
            break;
        }
    }
    dbprintlf("After loop, accept retval = %d", accept_retval);
    if (accept_retval < 0)
    {
        dbprintlf("Accept failed on SSL");
        ERR_print_errors_fp(stderr);
        client->CloseSSLConn();
        return -4;
    }
    client->ssl_ready = true;
    return 1;
}
