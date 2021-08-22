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
#include "network.hpp"
#include "meb_debug.hpp"

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, int polling_rate)
    : NetData()
{
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

NetDataServer::NetDataServer(NetPort listening_port)
    : NetData()
{
    this->listening_port = (int)listening_port;
};

NetFrame::NetFrame(unsigned char *payload, ssize_t size, NetType type, NetVertex destination) : payload(nullptr)
{
    hdr->payload_size = -1;
    if (payload == nullptr || size == 0 || type == NetType::POLL)
    {
        if (payload != nullptr || size != 0 || type != NetType::POLL)
        {
            dbprintlf(FATAL "Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
            throw std::invalid_argument("Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
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

    if (network_data->socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->socket);
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

    // Set the header area of the buffer.
    memcpy(buffer, this->hdr, sizeof(NetFrameHeader));

    // Copy the payload into the buffer.
    memcpy(buffer + sizeof(NetFrameHeader), this->payload, payload_buffer_size);

    // Set the footer area of the buffer.
    memcpy(buffer + sizeof(NetFrameHeader) + payload_buffer_size, this->ftr, sizeof(NetFrameFooter));

    // Set frame_size to malloc_size, the bytes allocated for the sendable buffer, to track how many bytes should send.
    this->frame_size = malloc_size;

    send_size = send(network_data->socket, buffer, malloc_size, 0);

    free(buffer);

    return send_size;
}

ssize_t NetFrame::recvFrame(NetData *network_data)
{
    if (!(network_data->connection_ready))
    {
        dbprintlf(YELLOW_FG "Connection is not ready, send aborted.");
        return -1;
    }

    if (network_data->socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->socket);
        return -1;
    }

    // Verify GUID.
    NetFrameHeader header;
    int offset = 0;
    int recv_attempts = 0;

    do
    {
        int sz = recv(network_data->socket, header.bytes + offset, 1, MSG_WAITALL);
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
        int sz = recv(network_data->socket, header.bytes + offset, sizeof(NetFrameHeader) - offset, MSG_WAITALL);
        if (sz < 0)
            break;
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
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
        int sz = recv(network_data->socket, this->payload + offset, payload_buffer_size - offset, MSG_WAITALL);
        if (sz < 0)
        {
            // Connection broken mid-receive-payload.
            return -4;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
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
        int sz = recv(network_data->socket, footer.bytes + offset, sizeof(NetFrameFooter) - offset, MSG_WAITALL);
        if (sz < 0)
        {
            // Connection broken.
            return -4;
        }
        if (sz == 0)
        {
            recv_attempts++;
            if (recv_attempts > 20)
            {
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
        return hdr->payload_size;
    }

    return -1;
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
            delete polling_frame;
        }
        else
        {
            gs_connect_to_server(network_data);
        }
        usleep(network_data->polling_rate * 1000000);
    }

    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
    if (network_data->thread_status > 0)
    {
        network_data->thread_status = 0;
    }
    return nullptr;
}

int gs_connect_to_server(NetDataClient *network_data)
{
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s.", network_data->ip_addr);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    if ((network_data->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, network_data->ip_addr, &network_data->server_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(network_data->socket, (struct sockaddr *)network_data->server_ip, sizeof(network_data->server_ip), 1) < 0)
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
        setsockopt(network_data->socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout); // connection timeout set
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
        else if (connect_status != 2 * sizeof(NetVertex))
        {
            dbprintlf("Server reply payload size mismatch");
            frame->print();
            connect_status = -6;
        }
        else
        {
            NetVertex vertices[2];
            frame->retrievePayload(vertices, 2 * sizeof(NetVertex));
            network_data->vertex = vertices[0];
            network_data->server_vertex = vertices[1];
            network_data->connection_ready = true;
            connect_status = 1;
        }
        free(_network_data);
        delete frame;
    }

    return connect_status;
}

// TODO: gs_accept()

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