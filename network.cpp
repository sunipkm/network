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

static int ssl_init = 0;

static SSL_CTX *sslctx = NULL;

// TODO: Generate key for SSL connection automatically

void InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    sslctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
    int use_cert = SSL_CTX_use_certificate_file(sslctx, "./cert.pem", SSL_FILETYPE_PEM);
    int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, "./key.pem", SSL_FILETYPE_PEM);
    if (use_cert != 1 || use_prv != 1)
        ssl_init = 0;
}

void DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

int NetData::open_ssl_conn()
{
    if (ssl_init && connection_ready)
    {
        cssl = SSL_new(sslctx);
        if (!SSL_set_fd(cssl, _socket))
        {
            dbprintlf("Could not open SSL connection");
            return -1;
        }
        int ssl_err = SSL_accept(cssl);
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
    if (ssl_init && ssl_ready)
    {
        ssl_ready = false;
        SSL_shutdown(cssl);
        SSL_free(cssl);
    }
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
    if (--ssl_init == 0)
        DestroySSL();
}

NetClient::~NetClient()
{
    Close();
    if (--ssl_init == 0)
        DestroySSL();
}

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, int polling_rate)
    : NetData()
{
    if (ssl_init++ == 0)
    {
        InitializeSSL();
    }
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

NetDataServer::NetDataServer(NetPort listening_port, int clients)
    : NetData()
{
    if (ssl_init++ == 0)
    {
        InitializeSSL();
    }
    srand(time(NULL));
    origin = rand();
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

    if (--ssl_init == 0)
        DestroySSL();
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
    ftr->netstat = 0x0;
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
        ftr->netstat = footer.netstat;
        ftr->termination = footer.termination;
    }

    // Validate the data we read as a valid NetFrame.
    if (this->validate())
    {
        retval = payload_buffer_size + sizeof(NetFrameFooter) + sizeof(NetFrameHeader);
    }

    if (this->getType() == NetType::SSL_REQ)
    {
        int ack_cmd = (int)NetType::SSL_REQ;
        NetFrame *ackframe = new NetFrame(&ack_cmd, sizeof(int), ssl_init ? NetType::ACK : NetType::NACK, network_data->origin);
        retval = ackframe->sendFrame(network_data);
        if (retval > 0)
        {
            network_data->open_ssl_conn();
        }
    }

    return retval;
}

int NetData::RequestSSL()
{
    if (ssl_init == 0)
    {
        dbprintlf("Could not request SSL connection, SSL not initialized.\n");
        return -1;
    }
    NetFrame *frame = new NetFrame(NULL, 0, NetType::SSL_REQ, origin);
    int retval = frame->sendFrame(this);
    delete frame;
    frame = new NetFrame();
    retval = frame->recvFrame(this);
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
    dbprintlf("Type ------------ %d", (int)hdr->type);
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
    dbprintlf("NetStat --------- 0x%x", ftr->netstat);
    dbprintlf("Termination ----- 0x%04x", ftr->termination);
    printf("\n");
}

void NetFrame::printNetstat()
{
    dbprintlf(BLUE_FG "NETWORK STATUS (%d)", ftr->netstat);
    dbprintf("GUI Client ----- ");
    ((ftr->netstat & 0x80) == 0x80) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Roof UHF ------- ");
    ((ftr->netstat & 0x40) == 0x40) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Roof X-Band ---- ");
    ((ftr->netstat & 0x20) == 0x20) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Haystack ------- ");
    ((ftr->netstat & 0x10) == 0x10) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
    dbprintf("Track ---------- ");
    ((ftr->netstat & 0x8) == 0x8) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
}

int NetFrame::setNetstat(uint8_t netstat)
{
#ifdef GSNID
    if (strcmp(GSNID, "server") == 0)
    {
        this->netstat = netstat;
        return 1;
    }
    else
    {
        dbprintlf(RED_FG "Only the Ground Station Network Server may set netstat.");
        return -1;
    }
#endif

    dbprintlf(FATAL "GSNID not defined. Please ensure one of the following exists:");
    dbprintlf(RED_FG "#define GSNID \"guiclient\"");
    dbprintlf(RED_FG "#define GSNID \"server\"");
    dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
    dbprintlf(RED_FG "#define GSNID \"roofxband\"");
    dbprintlf(RED_FG "#define GSNID \"haystack\"");
    dbprintlf(RED_FG "#define GSNID \"track\"");
    dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
    return -1;
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
        free(_network_data);
        delete frame;
    }
    network_data->recv_active = true;
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
    NetVertex vertices[2];
    vertices[0] = rand();
    vertices[1] = serv->origin;
    NetFrame *frame = new NetFrame((void *)vertices, sizeof(vertices), NetType::SRV, vertices[0]);

    int bytes = frame->sendFrame(client);

    if (bytes <= 0)
    {
        dbprintlf("Cound not send vertex identifiers, closing connection");
    }

    return client->_socket;
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