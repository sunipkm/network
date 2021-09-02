/**
 * @file network.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.07.30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <new>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <assert.h>
#include "network.hpp"
#include "meb_debug.hpp"
#ifdef __linux__
#include <signal.h>
#endif

// #include <openssl/applink.c>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

static int ssl_lib_init = 0;

// TODO: Generate key for SSL connection automatically

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
    }
}

SSL_CTX *InitializeSSLServer(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
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

SSL_CTX *InitializeSSLClient(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
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
            CloseSSLConn();
            return -1;
        }
        ssl_ready = true;
        return 1;
    }
    return -1;
}

void NetData::CloseSSLConn()
{
    if (cssl != NULL)
    {
        ssl_ready = false;
        SSL_shutdown(cssl);
        SSL_free(cssl);
        cssl = NULL;
    }
}

void NetData::Close()
{
    CloseSSLConn();
    connection_ready = false;
    close(_socket);
    _socket = -1;
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

NetClient::~NetClient()
{
    Close();
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    ctx = NULL;
    DestroySSL();
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
    server_ip->sin_family = AF_INET;
    server_ip->sin_port = htons((int)server_port);
    devclass = dclass;
    devId = did;
    origin = ((uint32_t)dclass << 8) | ((uint32_t)did);
};

NetDataServer::NetDataServer(NetPort listening_port, int clients)
{
    _NetDataServer(listening_port, clients);
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
                   &opt, sizeof(opt)))
    {
        dbprintlf("setsockopt reuseaddr");
        throw std::invalid_argument("setsockopt reuseaddr");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                   &opt, sizeof(opt)))
    {
        dbprintlf("setsockopt reuseport");
        throw std::invalid_argument("setsockopt reuseport");
    }

    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags != -1);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

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

    if (pthread_create(&accept_thread, NULL, gs_accept_thread, this) != 0)
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
    pthread_cancel(accept_thread);

    if (fd > 0)
    {
        close(fd);
        fd = -1;
    }

    if (clients != nullptr)
        delete[] clients;
    clients = nullptr;
    num_clients = 0;

    if (auth_token != nullptr)
        delete auth_token;
    auth_token = nullptr;
}

NetFrame::NetFrame(void *payload, ssize_t size, int payload_type, NetType type, FrameStatus status, NetVertex destination) : payload(nullptr)
{
    hdr->payload_size = -1;
    if ((payload == nullptr || size == 0) && (type != NetType::POLL))
    {
        dbprintlf(FATAL "Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
        throw std::invalid_argument("Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
    }

    if ((int)type < (int)NetType::POLL || (int)type > (int)NetType::MAX)
    {
        dbprintlf(FATAL "Invalid or unknown NetType.");
        throw std::invalid_argument("Invalid or unknown NetType.");
    }

    hdr->guid = NETFRAME_GUID;
    hdr->type = (int)type;
    hdr->status = (int)status;
    hdr->destination = destination;

    hdr->payload_type = payload_type;
    hdr->payload_size = size;

    // Enforces a minimum payload capacity, even if the payload size if less.
    // payload_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;
    size_t malloc_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;

    // Payload too large error.
    if (hdr->payload_size > NETFRAME_MAX_PAYLOAD_SIZE)
    {
        throw std::invalid_argument("Payload size larger than 0xfffe0.");
    }

    this->payload = new uint8_t[malloc_size];

    if (this->payload == nullptr)
    {
        throw std::bad_alloc();
    }

    if (malloc_size == NETFRAME_MIN_PAYLOAD_SIZE)
    {
        memset(this->payload, 0x0, NETFRAME_MIN_PAYLOAD_SIZE);
    }

    // Check if payload is nullptr, and allocate memory if it is not.
    if (payload != nullptr && size > 0)
    {
        memcpy(this->payload, payload, hdr->payload_size);
    }

    hdr->crc1 = internal_crc16(this->payload, malloc_size);
    ftr->crc2 = hdr->crc1;
    ftr->termination = NETFRAME_TERMINATOR;
}

NetFrame::~NetFrame()
{
    if (payload != nullptr)
        delete[] payload;
    payload = nullptr;
    memset(hdr, 0x0, sizeof(NetFrameHeader));
    memset(ftr, 0x0, sizeof(NetFrameFooter));
    hdr->payload_size = -1;
}

int NetFrame::retrievePayload(void *storage, ssize_t capacity)
{
    if (capacity < hdr->payload_size)
    {
        dbprintlf("Capacity less than payload size (%ld < %d).\n", capacity, hdr->payload_size);
        return -1;
    }

    memcpy(storage, payload, hdr->payload_size);

    return 1;
}

ssize_t NetFrame::sendFrame(NetData *network_data)
{
    if (!(network_data->connection_ready))
    {
        dbprintlf(YELLOW_FG "Connection is not ready, send aborted.");
        return -1;
    }

    if (network_data->_socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->_socket);
        return -1;
    }

    if (!validate())
    {
        dbprintlf(RED_FG "Frame validation failed, send aborted.");
        return -1;
    }

    if (hdr->payload_size < 0)
    {
        dbprintlf(RED_FG "Frame was constructed using NetFrame() not NetFrame(unsigned char *, ssize_t, NetType, NetVertex), has not had data read into it, and is therefore unsendable.");
        return -1;
    }

    size_t payload_buffer_size = hdr->payload_size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : hdr->payload_size;

    ssize_t send_size = 0;
    uint8_t *buffer = nullptr;
    ssize_t malloc_size = sizeof(NetFrameHeader) + payload_buffer_size + sizeof(NetFrameFooter);
    buffer = (uint8_t *)malloc(malloc_size);

    if (buffer == nullptr)
    {
        return -1;
    }

    // To send a NetFrame which contains a dynamically allocated payload buffer, we must construct a sendable buffer of three components:
    // 1. Header
    // 2. Payload
    // 3. Footer
    this->hdr->origin = network_data->origin;
    // Set the header area of the buffer.
    memcpy(buffer, this->hdr, sizeof(NetFrameHeader));

    // Copy the payload into the buffer.
    memcpy(buffer + sizeof(NetFrameHeader), this->payload, payload_buffer_size);

    // Set the footer area of the buffer.
    memcpy(buffer + sizeof(NetFrameHeader) + payload_buffer_size, this->ftr, sizeof(NetFrameFooter));

    // Set frame_size to malloc_size, the bytes allocated for the sendable buffer, to track how many bytes should send.
    this->frame_size = malloc_size;

    if (network_data->ssl_ready && network_data->cssl != NULL)
        send_size = SSL_write(network_data->cssl, buffer, malloc_size);
    else
        send_size = send(network_data->_socket, buffer, malloc_size, MSG_NOSIGNAL);

    if (send_size < 0)
    {
        dbprintlf("Connection closed by server/client\n");
        network_data->Close();
    }

    free(buffer);

    return send_size;
}

ssize_t NetFrame::recvFrame(NetData *network_data)
{
    ssize_t retval = -1;

    if (!(network_data->connection_ready))
    {
        dbprintlf(YELLOW_FG "Connection is not ready, send aborted.");
        return -1;
    }

    if (network_data->_socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->_socket);
        return -1;
    }

    // Verify GUID.
    NetFrameHeader header;
    memset(header.bytes, 0x0, sizeof(NetFrameHeader));
    int offset = 0;
    int recv_attempts = 0;

    do
    {
        int sz;
        if (network_data->ssl_ready && network_data->cssl != NULL)
            sz = SSL_read(network_data->cssl, header.bytes + offset, 1);
        else
            sz = recv(network_data->_socket, header.bytes + offset, 1, MSG_WAITALL);
        if (sz < 0)
        {
            // Connection broken.
            break;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                network_data->Close();
                return -404;
            }
        }
        if ((sz == 1) && (header.bytes[offset] == (uint8_t)(NETFRAME_GUID >> (offset * 8))))
        {
            offset++;
        }
        else
        {
            offset = 0;
        }
    } while (offset < sizeof(NETFRAME_GUID));

    recv_attempts = 0;

    // Receive the rest of the header.
    do
    {
        int sz;
        if (network_data->ssl_ready && network_data->cssl != NULL)
            sz = SSL_read(network_data->cssl, header.bytes + offset, sizeof(NetFrameHeader) - offset);
        else
            sz = recv(network_data->_socket, header.bytes + offset, sizeof(NetFrameHeader) - offset, MSG_WAITALL);
        if (sz < 0)
            break;
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                network_data->Close();
                return -404;
            }
        }
        offset += sz;
    } while (offset < sizeof(NetFrameHeader));

    size_t payload_buffer_size = 0;

    if (offset == sizeof(NetFrameHeader)) // success
    {
        hdr->guid = header.guid;
        hdr->type = header.type;
        hdr->status = header.status;
        hdr->origin = header.origin;
        hdr->destination = header.destination;
        hdr->payload_size = header.payload_size;
        hdr->payload_type = header.payload_type;
        hdr->unused = header.unused;
        hdr->crc1 = header.crc1;

        payload_buffer_size = hdr->payload_size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : hdr->payload_size;

        if (payload_buffer_size <= NETFRAME_MAX_PAYLOAD_SIZE)
        {
            this->payload = (uint8_t *)malloc(payload_buffer_size);
        }
        else
        {
            return -2; // invalid size
        }
    }
    else // failure
    {
        return -1;
    }

    if (this->payload == nullptr)
    {
        return -3; // malloc failed
    }

    offset = 0;

    recv_attempts = 0;

    // Receive the payload.
    do
    {
        int sz;
        if (network_data->ssl_ready && network_data->cssl != NULL)
            sz = SSL_read(network_data->cssl, this->payload + offset, payload_buffer_size - offset);
        else
            sz = recv(network_data->_socket, this->payload + offset, payload_buffer_size - offset, MSG_WAITALL);
        if (sz < 0)
        {
            network_data->Close();
            return -4;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                network_data->Close();
                return -404;
            }
        }
        offset += sz;
    } while (offset < payload_buffer_size);

    offset = 0;

    NetFrameFooter footer;

    recv_attempts = 0;

    // Receive the footer.
    do
    {
        int sz;
        if (network_data->ssl_ready && network_data->cssl != NULL)
            sz = SSL_read(network_data->cssl, footer.bytes + offset, sizeof(NetFrameFooter) - offset);
        else
            sz = recv(network_data->_socket, footer.bytes + offset, sizeof(NetFrameFooter) - offset, MSG_WAITALL);
        if (sz < 0)
        {
            network_data->Close();
            return -4;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
                network_data->Close();
                return -404;
            }
        }
        offset += sz;
    } while (offset < sizeof(NetFrameFooter));

    // memcpy
    if (offset == sizeof(NetFrameFooter))
    {
        ftr->crc2 = footer.crc2;
        ftr->termination = footer.termination;
    }

    // Validate the data we read as a valid NetFrame.
    if (this->validate())
    {
        retval = payload_buffer_size + sizeof(NetFrameFooter) + sizeof(NetFrameHeader);
    }
#ifdef NETWORK_DEBUG
    else
    {
        dbprintlf("Validation failed on frame");
    }
#endif

    return retval;
}

// ssize_t NetFrame::recvFrame(NetClient *network_data)
// {
//     NetData *client = (NetData *)network_data;
//     NetDataServer *serv = network_data->serv;
//     ssize_t retval = recvFrame(client);

//     if (retval <= 0) // error
//         return retval;

//     if (this->getType() == NetType::SSL_REQ && network_data->server == false) // SSL request received from client
//     {
//         int ack_cmd = (int)NetType::SSL_REQ;
//         NetType ret = NetType::NACK;
//         sha1_hash_t auth;
//         if (!ssl_lib_init) // initialized
//         {
//             dbprintlf(RED_FG "SSL Library not initialized");
//         }
//         else if (serv->GetAuthToken() == nullptr)
//         {
//             dbprintlf(RED_FG "Authentication token null");
//         }
//         else if (serv->GetAuthToken()->hash() == 0)
//         {
//             dbprintlf(RED_FG "Authentication token not set up");
//         }
//         else if (getPayloadSize() < sizeof(sha1_hash_t))
//         {
//         }
//         else if (retrievePayload(auth.bytes, sizeof(auth)) < 0)
//         {
//             dbprintlf(RED_FG "Could not obtain authentication token\n");
//         }
//         else if (!serv->GetAuthToken()->equal(auth))
//         {
//             dbprintlf(RED_FG "Authentication token mismatch");
//         }
//         else
//             ret = NetType::ACK;
//         NetFrame *ackframe = new NetFrame(&ack_cmd, sizeof(int), ret, network_data->origin);
//         retval = ackframe->sendFrame(network_data); // ACK/NACK SSL request
//         if ((retval > 0) && (ret == NetType::ACK))  // if ACK
//         {
//             network_data->ssl_ready = true;  // Set SSL ready
//             if (gs_accept_ssl(network_data)) // Set up SSL as server
//                 return retval;
//             else
//                 return -101;
//         }
//     }

//     return retval;
// }

// int NetDataClient::RequestSSL(sha1_hash_t *auth)
// {
//     if (ssl_lib_init == 0)
//     {
//         dbprintlf("Could not request SSL connection, SSL not initialized.\n");
//         return -1;
//     }
//     if (server)
//     {
//         dbprintlf("Server can not initiate an SSL request");
//         return -1;
//     }
//     NetFrame *frame = new NetFrame(auth->bytes, sizeof(sha1_hash_t), NetType::SSL_REQ, origin);
//     int retval = frame->sendFrame(this); // send request
//     delete frame;
//     frame = new NetFrame();
//     retval = frame->recvFrame(this);                                                  // receive N/ACK
//     if (retval > 0 && connection_ready && frame->getPayloadSize() == sizeof(NetType)) // received N/ACK
//     {
//         NetType cmdreply = NetType::MAX;
//         if ((frame->getType() == NetType::ACK) || (frame->getType() == NetType::NACK))
//         {
//             frame->retrievePayload(&cmdreply, sizeof(NetType));
//         }
//         if ((cmdreply == NetType::SSL_REQ) && (frame->getType() == NetType::ACK)) // SSL request granted
//         {
//             for (int i = 0; (i < 20) && (open_ssl_conn() < 0); i++)
//             {
//                 dbprintlf("Open connection error");
//                 usleep(100000);
//             }
//         }
//         else
//         {
//             return -1;
//         }
//     }
//     return retval;
// }

int NetFrame::validate()
{
    if (hdr->guid != NETFRAME_GUID)
    {
        return -1;
    }
    else if ((hdr->type < (int)NetType::POLL) || (hdr->type > (int)NetType::MAX))
    {
        return -2;
    }
    else if ((payload == nullptr) || (hdr->payload_size == 0) || (hdr->type == (int)NetType::POLL))
    {
        // dbprintlf(YELLOW_FG "payload == NULL: %d; payload_size: %d; type == NetType::POLL: %d", payload == NULL, payload_size, type == NetType::POLL);
        if ((hdr->payload_size != 0) || (hdr->type != (uint32_t)NetType::POLL))
        {
            return -3;
        }
    }
    else if ((hdr->payload_size < 0) || (hdr->payload_size > NETFRAME_MAX_PAYLOAD_SIZE))
    {
        return -6;
    }
    else if (hdr->crc1 != ftr->crc2)
    {
        dbprintlf("CRC at header 0x%04x does not match CRC at footer 0x%04x", hdr->crc1, ftr->crc2);
    }
    else if (hdr->crc1 != internal_crc16(payload, hdr->payload_size))
    {
        return -8;
    }
    else if (ftr->termination != NETFRAME_TERMINATOR)
    {
        return -9;
    }
    return 1;
}

void NetFrame::print()
{
    dbprintlf(BLUE_FG "NETWORK FRAME");
    dbprintlf("GUID ------------ 0x%08x", hdr->guid);
    dbprintlf("Frame Type ------ 0x%02x", (int)hdr->type);
    dbprintlf("Frame Status ---- 0x%02x", (int)hdr->status);
    dbprintlf("Destination ----- 0x%x", (int)hdr->destination);
    dbprintlf("Origin ---------- 0x%x", (int)hdr->origin);
    dbprintlf("Payload type ---- %d", hdr->payload_type);
    dbprintlf("Payload Size ---- %d", hdr->payload_size);
    dbprintlf("CRC1 ------------ 0x%04x", hdr->crc1);
    dbprintf("Payload ---- (HEX)");
    for (int i = 0; i < hdr->payload_size; i++)
    {
        if ((i % 2) == 0)
        {
            printf(BLUE_FG "%02x" RESET_ALL, payload[i]);
        }
        else
        {
            printf("%02x", payload[i]);
        }
    }
    printf("\n");
    dbprintlf("CRC2 ------------ 0x%04x", ftr->crc2);
    dbprintlf("Termination ----- 0x%04x", ftr->termination);
    printf("\n");
}

void *gs_polling_thread(void *args)
{
    dbprintlf(BLUE_FG "Beginning polling thread.");
    NetDataClient *network_data = (NetDataClient *)args;
    sleep(1);
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
        usleep(network_data->polling_rate * 1000);
    }
    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
    return nullptr;
}

void *gs_accept_thread(void *args)
{
    NetDataServer *serv = (NetDataServer *)args;
    while (!serv->listen_done)
    {
        for (int i = 0; i < serv->num_clients; i++)
        {
            gs_accept(serv, i);
        }
        sleep(1);
    }
    return NULL;
}

int gs_accept_ssl(NetClient *);

int NetDataClient::ConnectToServer()
{
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s.", ip_addr);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    if ((_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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
        dbprintlf(RED_FG "Connection failure.");
        connect_status = -3;
    }
    else
    {
        connect_status = 1;
        connection_ready = true;
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
#ifndef __linux__
    setsockopt(_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
    int retval;
    NetVertex server_v;
    NetFrame *frame;
    // Step 1. Receive server ping
    frame = new NetFrame();
    for (int i = 0; (i < 20) && (frame->recvFrame(this) < 0); i++)
        ;
    if (frame->getType() != NetType::POLL)
    {
        dbprintlf("Did not receive a poll packet, received %d", frame->getType());
        Close();
        delete frame;
        return -2;
    }
    server_v = frame->getOrigin();
    dbprintlf("Server Origin: 0x%x", server_v);
    delete frame;
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
    for (int i = 0; (i < 20) && (frame->recvFrame(this) < 0); i++)
        ;
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

    client->connection_ready = true;
    int set = 1;
#ifndef __linux__
    setsockopt(client->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
    NetFrame *frame;
    // Step 1. Poll the client for device class and type
    frame = new NetFrame(NULL, 0, 0, NetType::POLL, FrameStatus::NONE, 0); // vertex does not matter at this point
    int bytes = frame->sendFrame(client);
    delete frame;
    if (bytes <= 0)
    {
        dbprintlf("Could not poll client, closing connection");
        client->Close();
        return -5;
    }
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
    for (int i = 0; (i < 20) && (frame->recvFrame(client) < 0); i++)
        ;
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
    vertices[0] = (
        {
            int vertex = rand();
            while (vertex < 0xffff)
                vertex = rand();
            vertex & 0xffff0000;
        });
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
    usleep(20000);
    // Step 5. Receive ack
    int retval;
    frame = new NetFrame();
    for (int i = 0; i < 20; i++)
    {
        retval = frame->recvFrame(client);
        if (retval > 0)
            break;
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
                usleep(10000);
            }
            else if (err == SSL_ERROR_WANT_WRITE)
            {
                usleep(10000);
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

int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s)
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