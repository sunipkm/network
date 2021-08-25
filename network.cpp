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

// #include <openssl/applink.c>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

static int ssl_lib_init = 0;

enum SrvCmdTypes
{
    SSL_AUTH_TOKEN = 0x2f, // SSL authentication token
    SET_CLIENT_VERTEX,     // Set client class and device number
    GET_CLIENT_LIST,       // Get list of clients of the same class
    POLL_CLIENT,           // Poll a specific client
    SRV_CMDS_MAX           // last element
};

enum SrvDataTypes
{
    VERTEX_IDENT = 0x4f, // Vertex identification information
    CLIENT_LIST,         // List of clients
    SRV_DATA_MAX
}

#define MAX_SERVER_JOBS 100
/**
 * @brief This struct allocates the array of pthread_t for dispatching receiver jobs
 * 
 */
typedef struct
{
    int num_jobs = MAX_SERVER_JOBS;
    pthread_t *job_thread = nullptr;
    bool *active = nullptr;
    bool allocated = false;
} ServerJobs;

static ServerJobs joblist[1];

void InitializeSSLLibrary()
{
    if (ssl_lib_init++ == 0)
    {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();

        if (!joblist->allocated)
        {
            joblist->job_thread = new pthread_t[joblist->num_jobs];
            if (joblist->job_thread == nullptr)
                throw std::bad_alloc();
            joblist->active = new bool[joblist->num_jobs];
            if (joblist->active == nullptr)
                throw std::bad_alloc();
            for (int i = joblist->num_jobs; i > 0; i--)
            {
                joblist->active = false;
            }
            joblist->allocated = true;
        }
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
    ERR_free_strings();
    EVP_cleanup();
}

int NetDataClient::open_ssl_conn()
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
            close_ssl_conn();
            return -1;
        }
        ssl_ready = true;
        return 1;
    }
    return -1;
}

void NetData::close_ssl_conn()
{
    if (cssl != NULL)
    {
        ssl_ready = false;
        SSL_shutdown(cssl);
        SSL_free(cssl);
        cssl = NULL;
    }
    if (ctx != NULL)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    DestroySSL();
}

void NetData::Close()
{
    if (ssl_ready)
        close_ssl_conn();
    connection_ready = false;
    close(_socket);
    _socket = -1;
}

NetDataClient::~NetDataClient()
{
    Close();
}

NetClient::~NetClient()
{
    Close();
}

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, int polling_rate)
    : NetData()
{
    ctx = InitializeSSLClient();
    if (ip_addr == NULL)
        strcpy(this->ip_addr, "127.0.0.1");
    else
    {
        strncpy(this->ip_addr, ip_addr, sizeof(this->ip_addr));
    }
    this->polling_rate = polling_rate;
    strcpy(disconnect_reason, "N/A");
    server_ip->sin_family = AF_INET;
    server_ip->sin_port = htons((int)server_port);
};

NetDataServer::NetDataServer(NetPort listening_port, int clients, sha1_hash_t auth_token)
{
    this->auth_token = new sha1_hash_t();
    InitializeSSLLibrary();
    _NetDataServer(listening_port, clients);
    this->auth_token->copy(auth_token.bytes);
}

void NetDataServer::_NetDataServer(NetPort listening_port, int clients)
{
    server = true;
    srand(time(NULL));
    origin = rand() | 0x00008000; // Ensure Byte 1 of server NetVertex is set
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
    }

    if (pthread_create(&accept_thread, NULL, gs_accept_thread, this) != 0)
    {
        dbprintlf("Could not start accept thread");
    }
};

NetClient *NetDataServer::GetClient(int id)
{
    if (id >= num_clients)
    {
        dbprintlf("Invalid client ID %d, max client ID %d", id, num_clients - 1);
        return NULL;
    }
    return &(clients[id]);
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

NetFrame::NetFrame(void *payload, ssize_t size, NetType type, NetVertex destination) : payload(nullptr)
{
    hdr->payload_size = -1;
    if (payload == nullptr || size == 0 || type == NetType::POLL || type == NetType::SSL_REQ)
    {
        if ((payload != nullptr) || (size != 0))
        {
            if (!(type == NetType::POLL || type == NetType::SSL_REQ))
            {
                dbprintlf(FATAL "Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
                throw std::invalid_argument("Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
            }
        }
    }

    if ((int)type < (int)NetType::POLL || (int)type > (int)NetType::MAX)
    {
        dbprintlf(FATAL "Invalid or unknown NetType.");
        throw std::invalid_argument("Invalid or unknown NetType.");
    }

    hdr->guid = NETFRAME_GUID;
    hdr->type = (int)type;
    hdr->destination = destination;

    hdr->payload_size = size;

    // Enforces a minimum payload capacity, even if the payload size if less.
    // payload_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;
    size_t malloc_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;

    // Payload too large error.
    if (hdr->payload_size > NETFRAME_MAX_PAYLOAD_SIZE)
    {
        throw std::invalid_argument("Payload size larger than 0xfffe4.");
    }

    this->payload = (uint8_t *)malloc(malloc_size);

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
        free(payload);
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

    if (network_data->ssl_ready)
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
        if (network_data->ssl_ready)
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
        if (network_data->ssl_ready)
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
        hdr->origin = header.origin;
        hdr->destination = header.destination;
        hdr->payload_size = header.payload_size;
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
        if (network_data->ssl_ready)
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
        if (network_data->ssl_ready)
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

ssize_t NetFrame::recvFrame(NetClient *network_data)
{
    NetData *client = (NetData *)network_data;
    NetDataServer *serv = network_data->serv;
    ssize_t retval = recvFrame(client);

    if (retval <= 0) // error
        return retval;

    if (this->getType() == NetType::SSL_REQ && network_data->server == false) // SSL request received from client
    {
        int ack_cmd = (int)NetType::SSL_REQ;
        NetType ret = NetType::NACK;
        sha1_hash_t auth;
        if (!ssl_lib_init) // initialized
        {
            dbprintlf(RED_FG "SSL Library not initialized");
        }
        else if (serv->GetAuthToken() == nullptr)
        {
            dbprintlf(RED_FG "Authentication token null");
        }
        else if (serv->GetAuthToken()->hash() == 0)
        {
            dbprintlf(RED_FG "Authentication token not set up");
        }
        else if (getPayloadSize() < sizeof(sha1_hash_t))
        {
        }
        else if (retrievePayload(auth.bytes, sizeof(auth)) < 0)
        {
            dbprintlf(RED_FG "Could not obtain authentication token\n");
        }
        else if (!serv->GetAuthToken()->equal(auth))
        {
            dbprintlf(RED_FG "Authentication token mismatch");
        }
        else
            ret = NetType::ACK;
        NetFrame *ackframe = new NetFrame(&ack_cmd, sizeof(int), ret, network_data->origin);
        retval = ackframe->sendFrame(network_data); // ACK/NACK SSL request
        if ((retval > 0) && (ret == NetType::ACK))  // if ACK
        {
            network_data->ssl_ready = true;  // Set SSL ready
            if (gs_accept_ssl(network_data)) // Set up SSL as server
                return retval;
            else
                return -101;
        }
    }

    return retval;
}

int NetDataClient::RequestSSL(sha1_hash_t *auth)
{
    if (ssl_lib_init == 0)
    {
        dbprintlf("Could not request SSL connection, SSL not initialized.\n");
        return -1;
    }
    if (server)
    {
        dbprintlf("Server can not initiate an SSL request");
        return -1;
    }
    NetFrame *frame = new NetFrame(auth->bytes, sizeof(sha1_hash_t), NetType::SSL_REQ, origin);
    int retval = frame->sendFrame(this); // send request
    delete frame;
    frame = new NetFrame();
    retval = frame->recvFrame(this);                                                  // receive N/ACK
    if (retval > 0 && connection_ready && frame->getPayloadSize() == sizeof(NetType)) // received N/ACK
    {
        NetType cmdreply = NetType::MAX;
        if ((frame->getType() == NetType::ACK) || (frame->getType() == NetType::NACK))
        {
            frame->retrievePayload(&cmdreply, sizeof(NetType));
        }
        if ((cmdreply == NetType::SSL_REQ) && (frame->getType() == NetType::ACK)) // SSL request granted
        {
            for (int i = 0; (i < 20) && (open_ssl_conn() < 0); i++)
            {
                dbprintlf("Open connection error");
                usleep(100000);
            }
        }
        else
        {
            return -1;
        }
    }
    return retval;
}

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
    dbprintlf("Type ------------ 0x%02x", (int)hdr->type);
    dbprintlf("Destination ----- %d", (int)hdr->destination);
    dbprintlf("Origin ---------- %d", (int)hdr->origin);
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

    while (network_data->recv_active)
    {
        if (network_data->connection_ready)
        {
            NetFrame *polling_frame = new NetFrame(NULL, 0, NetType::POLL, network_data->server_vertex);
            polling_frame->sendFrame(network_data);
            polling_frame->print();
            delete polling_frame;
        }
        else
        {
            dbprintlf("Connect to server from poll\n");
            gs_connect_to_server(network_data);
        }
        if (network_data->polling_rate < 1000)
            network_data->polling_rate = 1000; // minimum 1 ms
        usleep(network_data->polling_rate * 1000);
    }

    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
    if (network_data->thread_status > 0)
    {
        network_data->thread_status = 0;
    }
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

int gs_connect_to_server(NetDataClient *network_data)
{
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s.", network_data->ip_addr);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    if ((network_data->_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, network_data->ip_addr, &network_data->server_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(network_data->_socket, (struct sockaddr *)network_data->server_ip, sizeof(network_data->server_ip), 1) < 0)
    {
        dbprintlf(RED_FG "Connection failure.");
        connect_status = -3;
    }
    else
    {
        // If the socket is closed, but recv(...) was already called, it will be stuck trying to receive forever from a socket that is no longer active. One way to fix this is to close the RX thread and restart it. Alternatively, we could implement a recv(...) timeout, ensuring a fresh socket value is used.
        // Here, we implement a recv(...) timeout.
        struct timeval timeout;
        timeout.tv_sec = RECV_TIMEOUT;
        timeout.tv_usec = 0;
        setsockopt(network_data->_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout); // connection timeout set
        int set = 1;
        setsockopt(network_data->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
        // Receive server acknowledgement
        NetFrame *frame = new NetFrame();
        NetDataClient *_network_data = (NetDataClient *)malloc(sizeof(NetDataClient));
        memcpy(_network_data, network_data, sizeof(NetDataClient));
        _network_data->connection_ready = true;
        if ((connect_status = frame->recvFrame(_network_data)) <= 0)
        {
            dbprintlf("Server did not reply with end point number assignment");
            connect_status = -4;
        }
        else if (frame->getType() != NetType::SRV)
        {
            dbprintlf("Server did not reply with an SRV type packet, reply type %d", frame->getType());
            connect_status = -5;
        }
        else if (frame->getPayloadSize() != 2 * sizeof(NetVertex))
        {
            dbprintlf("Server reply payload size mismatch");
            frame->print();
            connect_status = -6;
        }
        else
        {
            NetVertex vertices[2];
            frame->retrievePayload(vertices, 2 * sizeof(NetVertex));
            network_data->origin = vertices[0];
            network_data->server_vertex = vertices[1];
            network_data->connection_ready = true;
            connect_status = 1;
        }
        delete frame;
        free(_network_data);
    }
    usleep(10000);
    if (connect_status)
    {
        NetType acktype = NetType::SRV;
        NetFrame *frame = new NetFrame(&acktype, sizeof(NetType), NetType::ACK, network_data->server_vertex);
        int retval;
        if ((retval = frame->sendFrame(network_data)) < 0)
        {
            dbprintlf("Could not send ACK frame, error %d", retval);
            return retval;
        }
        delete frame;
    }
    network_data->recv_active = true;
    return connect_status;
}

int gs_accept(NetDataServer *serv, int client_id)
{
    // check if client ID is valid
    if (client_id >= serv->num_clients)
    {
        dbprintlf("Invalid client ID, max clients %d", serv->num_clients);
        return -1;
    }
    // get local pointer to client referenced by ID
    NetClient *client = serv->GetClient(client_id);
    // check if connection already available
    if (client->connection_ready)
    {
        return client->_socket;
    }
    // if not connected
    if (client->_socket <= 0)
    {
        client->client_addrlen = sizeof(struct sockaddr_in);
        client->_socket = accept(serv->fd, (struct sockaddr *)&(client->client_addr), (socklen_t *)&(client->client_addrlen)); // accept request
    }
    if (client->_socket <= 0) // connection attempt unsuccessful
        return client->_socket;

    client->connection_ready = true;
    int set = 1;
    // set socket option to not generate sigpipe if connection is broken
    setsockopt(client->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));

    // accept SSL connection
    if (gs_accept_ssl(client) < 0)
    {
        dbprintlf("Could not accept SSL connection");
        client->Close();
        return -1;
    }

    // Receive auth token
    NetFrame *frame = new NetFrame();
    int retval;
    for (int i = 0; i < 20; i++)
    {
        retval = frame->recvFrame(client);
        if (retval > 0)
            break;
    }

    if (retval <= 0)
    {
        dbprintlf("Could not receive frame for auth token check");
        client->Close();
        return -1;
    }

    // if authentication token
    FrameStatus ret = FrameStatus::NACK;
    if (this->GetType() == NetType::SRV && this->GetPayloadType() == SrvCmds::SSL_AUTH_TOKEN && this->GetStatus() == FrameStatus::NONE)
    {
        sha1_hash_t auth;
        if (!ssl_lib_init)
        {
            dbprintlf(RED_FG "SSL Library not initialized");
        }
        else if (serv->GetAuthToken() == nullptr)
        {
            dbprintlf(RED_FG "Authentication token null");
        }
        else if (serv->GetAuthToken()->hash() == 0)
        {
            dbprintlf(RED_FG "Authentication token not set up");
        }
        else if (getPayloadSize() != sizeof(sha1_hash_t))
        {
            dbprintlf(RED_FG "Authentication token size invalid");
        }
        else if (retrievePayload(auth.bytes, sizeof(auth)) < 0)
        {
            dbprintlf(RED_FG "Could not obtain authentication token\n");
        }
        else if (!serv->GetAuthToken()->equal(auth))
        {
            dbprintlf(RED_FG "Authentication token mismatch");
        }
        else
        {
            ret = FrameStatus::ACK;
        }
        delete frame;
    }
    else
    {
        // hang up
        // TODO: Black list IP address
        delete frame;
        dbprintlf("Could not receive frame for auth token check");
        client->Close();
        return -1;
    }

    if (ret == FrameStatus::ACK) // successful: Send NetVertex etc
    {
        NetVertex vertices[2];
        vertices[0] = rand() & 0xffff0000; // lower two bytes are unset, 65536 unique vertices can be allocated
        vertices[1] = serv->origin;
        client->origin = vertices[0];
        frame = new NetFrame((void *)vertices, sizeof(vertices), (int)SrvDataTypes::VERTEX_IDENT, vertices[0], ret);
    }
    else
    {
        frame = new NetFrame(NULL, 0, (int)SrvCmdTypes::SSL_AUTH_TOKEN, 0, ret);
        frame->sendFrame(client);
        delete frame;
        dbprintlf("Could not authenticate client");
        client->Close();
        return -1;
    }

    int bytes = frame->sendFrame(client);

    if (bytes <= 0)
    {
        dbprintlf("Cound not send vertex identifiers, closing connection");
        delete frame;
        client->Close();
        return -1;
    }

    delete frame;

    frame = new NetFrame();

    usleep(20000);

    ret = FrameStatus::NACK;
    for (int i = 0; i < 20; i++)
    {
        retval = frame->recvFrame(client);
        if (retval > 0)
            break;
    }
    if (retval < 0)
    {
        dbprintlf(FATAL "Did not receive acknowledgement: %d", retval);
        return retval;
    }
    else if (frame->GetType() != NetType::SRV)
    {
        dbprintlf(RED_FG "Expecting SRV, received %d", (int)frame->getType());
    }
    else if (frame->GetPayloadType() != (int)SrvCmdTypes::SET_CLIENT_VERTEX)
    {
        dbprintlf(REG_FG "Expecting SET_CLIENT_VERTEX, got %d", frame->GetPayloadType());
    }
    else if (frame->GetPayloadSize() != sizeof(NetVertex))
    {
        dbprintlf(REG_FG "Expecting payload size %d, got %d", sizeof(NetVertex), frame->GetPayloadSize());
    }
    else
    {
        // get the vertex payload
        NetVertex new_vertex = (NetVertex)0;
        frame->retrievePayload(&new_vertex, sizeof(NetVertex));
        if ((new_vertex & 0xffff0000) == client->origin)
        {
            client->origin = new_vertex;
            ret = FrameStatus::ACK;
        }
    }
    delete frame;

    frame = new NetFrame(&(client->origin), sizeof(NetVertex), (int)SrvCmdTypes::SET_CLIENT_VERTEX, client->origin, ret);
    frame->sendFrame(client);
    delete frame;

    if (ret == FrameStatus::ACK)
        return client->_socket;
    else
    {
        client->Close();
        return -1;
    }
}

int gs_accept_ssl(NetData *client)
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
    else if (!client->ssl_ready)
    {
        dbprintlf("SSL not ready");
        return 1;
    }
    client->ctx = InitializeSSLServer();
    if (client->ctx == NULL)
    {
        dbprintlf(FATAL "Could not initialize SSL context for the client");
        return -1;
    }
    client->cssl = SSL_new(client->ctx);
    if (client->cssl == NULL)
    {
        dbprintlf(FATAL "Could not allocate SSL connection");
        return -2;
    }
    if (!SSL_set_fd(client->cssl, client->_socket))
    {
        dbprintlf("Could not attach C socket to SSL socket");
        client->close_ssl_conn();
        return -3;
    }
    int accept_retval = 0;
    for (int i = 0; i < 100; i++)
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
    if (accept_retval < 0)
    {
        dbprintlf("Accept failed on SSL");
        ERR_print_errors_fp(stderr);
        client->close_ssl_conn();
        return -4;
    }
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