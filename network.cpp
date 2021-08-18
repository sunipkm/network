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
#include "network.hpp"
#include "meb_debug.hpp"

NetData::NetData()
{
    connection_ready = false;
    socket = -1;
};

NetDataClient::NetDataClient(NetPort server_port, int polling_rate)
    : NetData()
{
    ;
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

NetFrame::NetFrame(unsigned char *payload, ssize_t size, NetType type, NetVertex destination) : payload(nullptr), payload_size(0)
{
    if (payload == nullptr || size == 0 || type == NetType::POLL)
    {
        if (payload != nullptr || size != 0 || type != NetType::POLL)
        {
            dbprintlf(FATAL "Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
            throw std::invalid_argument("Invalid combination of NULL payload, 0 size, and/or POLL NetType.");
        }
    }

    if ((int)type < (int)NetType::POLL || (int)type > (int)NetType::TRACKING_DATA)
    {
        dbprintlf(FATAL "Invalid or unknown NetType.");
        throw std::invalid_argument("Invalid or unknown NetType.");
    }

    if ((int)destination < (int)NetVertex::CLIENT || (int)destination > (int)NetVertex::SERVER)
    {
        dbprintlf("Invalid or unknown NetVertex.");
        throw std::invalid_argument("Invalid or unknown NetVertex.");
    }

    // Figure out origin for ourselves.
#ifdef GSNID
    if (strcmp(GSNID, "guiclient") == 0)
    {
        origin = NetVertex::CLIENT;
    }
    else if (strcmp(GSNID, "server") == 0)
    {
        origin = NetVertex::SERVER;
    }
    else if (strcmp(GSNID, "roofuhf") == 0)
    {
        origin = NetVertex::ROOFUHF;
    }
    else if (strcmp(GSNID, "roofxband") == 0)
    {
        origin = NetVertex::ROOFXBAND;
    }
    else if (strcmp(GSNID, "haystack") == 0)
    {
        origin = NetVertex::HAYSTACK;
    }
    else if (strcmp(GSNID, "track") == 0)
    {
        origin = NetVertex::TRACK;
    }
    else
    {
        dbprintlf(FATAL "GSNID not recognized. Please ensure one of the following exists:");
        dbprintlf(RED_FG "#define GSNID \"guiclient\"");
        dbprintlf(RED_FG "#define GSNID \"server\"");
        dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
        dbprintlf(RED_FG "#define GSNID \"roofxband\"");
        dbprintlf(RED_FG "#define GSNID \"haystack\"");
        dbprintlf(RED_FG "#define GSNID \"track\"");
        dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
        throw std::invalid_argument("GSNID not recognized.");
    }
#endif
#ifndef GSNID
    dbprintlf(FATAL "GSNID not defined. Please ensure one of the following exists:");
    dbprintlf(RED_FG "#define GSNID \"guiclient\"");
    dbprintlf(RED_FG "#define GSNID \"server\"");
    dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
    dbprintlf(RED_FG "#define GSNID \"roofxband\"");
    dbprintlf(RED_FG "#define GSNID \"haystack\"");
    dbprintlf(RED_FG "#define GSNID \"track\"");
    dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
    throw std::invalid_argument("GSNID not defined.");
#endif
    guid = NETFRAME_GUID;
    this->type = type;
    this->destination = destination;

    // Enforces a minimum payload capacity, even if the payload size if less.
    payload_size = size < NETFRAME_MIN_PAYLOAD_SIZE ? NETFRAME_MIN_PAYLOAD_SIZE : size;

    // Payload too large error.
    if (payload_size > NETFRAME_MAX_PAYLOAD_SIZE)
    {
        throw std::invalid_argument("Payload size larger than 0xfffe4.");
    }

    this->payload = (uint8_t *)malloc(payload_size);

    if (this->payload == nullptr)
    {
        throw std::bad_alloc();
    }

    if (payload_size == NETFRAME_MIN_PAYLOAD_SIZE)
    {
        memset(this->payload, 0x0, NETFRAME_MIN_PAYLOAD_SIZE);
    }

    // Check if payload is nullptr, and allocate memory if it is not.
    if (payload != nullptr && size > 0)
    {
        memcpy(this->payload, payload, payload_size);
    }

    crc1 = internal_crc16(this->payload, payload_size);
    crc2 = internal_crc16(this->payload, payload_size);
    netstat = 0x0;
    termination = 0xAAAA;
}

NetFrame::~NetFrame()
{
    if (payload != nullptr)
        free(payload);
    payload = nullptr;
    payload_size = 0;
}

int NetFrame::retrievePayload(unsigned char *storage, ssize_t capacity)
{
    if (capacity < payload_size)
    {
        dbprintlf("Capacity less than payload size (%ld < %ld).\n", capacity, payload_size);
        return -1;
    }

    memcpy(storage, payload, payload_size);

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

    if (payload_size < 0)
    {
        dbprintlf(RED_FG "Frame was constructed using NetFrame() not NetFrame(unsigned char *, ssize_t, NetType, NetVertex), has not had data read into it, and is therefore unsendable.");
        return -1;
    }

    ssize_t send_size = 0;
    uint8_t *buffer = nullptr;
    ssize_t malloc_size = sizeof(NetFrameHeader) + this->payload_size + sizeof(NetFrameFooter);
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
    NetFrameHeader *header = (NetFrameHeader *)buffer;
    header->guid = this->guid;
    header->type = (uint32_t)this->type;
    header->origin = (uint32_t)this->origin;
    header->destination = (uint32_t)this->destination;
    header->payload_size = this->payload_size;
    header->crc1 = this->crc1;

    // Copy the payload into the buffer.
    memcpy(buffer + sizeof(NetFrameHeader), this->payload, this->payload_size);

    // Set the footer area of the buffer.
    NetFrameFooter *footer = (NetFrameFooter *)(buffer + sizeof(NetFrameHeader) + this->payload_size);
    footer->crc2 = this->crc2;
    footer->netstat = this->netstat;
    footer->termination = termination;

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

    do
    {
        int sz = recv(network_data->socket, header.bytes + offset, 1, MSG_WAITALL);
        if (sz < 0)
        {
            // Connection broken.
            break;
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

    // Receive the rest of the header.
    do
    {
        int sz = recv(network_data->socket, header.bytes + offset, sizeof(NetFrameHeader) - offset, MSG_WAITALL);
        if (sz < 0)
            break;
        offset += sz;
    } while (offset < sizeof(NetFrameHeader));

    if (offset == sizeof(NetFrameHeader)) // success
    {
        this->guid = header.guid;
        this->type = (NetType)header.type;
        this->origin = (NetVertex)header.origin;
        this->destination = (NetVertex)header.destination;
        this->payload_size = header.payload_size;
        this->crc1 = header.crc1;
        if ((payload_size >= 0) && (payload_size <= NETFRAME_MAX_PAYLOAD_SIZE))
        {
            this->payload = (uint8_t *)malloc(this->payload_size);
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

    // Receive the payload.
    do
    {
        int sz = recv(network_data->socket, this->payload + offset, this->payload_size - offset, MSG_WAITALL);
        if (sz < 0)
        {
            // Connection broken mid-receive-payload.
            free(this->payload);
            return -4;
        }
        offset += sz;
    } while (offset < this->payload_size);

    offset = 0;

    NetFrameFooter footer;

    // Receive the footer.
    do
    {
        int sz = recv(network_data->socket, footer.bytes + offset, sizeof(NetFrameFooter) - offset, MSG_WAITALL);
        if (sz < 0)
        {
            // Connection broken.
            free(this->payload);
            return -4;
        }
        offset += sz;
    } while (offset < sizeof(NetFrameFooter));

    // memcpy
    if (offset == sizeof(NetFrameFooter))
    {
        this->crc2 = footer.crc2;
        this->netstat = footer.netstat;
        this->termination = footer.termination;
    }

    // Validate the data we read as a valid NetFrame.
    if (this->validate())
    {
        return this->payload_size;
    }

    return -1;
}

int NetFrame::validate()
{
    if (guid != NETFRAME_GUID)
    {
        return -1;
    }
    else if ((int)type < (int)NetType::POLL || (int)type > (int)NetType::TRACKING_DATA)
    {
        return -2;
    }
    else if (payload == NULL || payload_size == 0 || type == NetType::POLL)
    {
        dbprintlf(YELLOW_FG "payload == NULL: %d; payload_size: %d; type == NetType::POLL: %d", payload == NULL, payload_size, type == NetType::POLL);
        if (payload_size != 0 || type != NetType::POLL)
        {
            return -3;
        }
    }
    else if ((int)origin < (int)NetVertex::CLIENT || (int)origin > (int)NetVertex::TRACK)
    {
        return -4;
    }
    else if ((int)destination < (int)NetVertex::CLIENT || (int)destination > (int)NetVertex::TRACK)
    {
        return -5;
    }
    else if (payload_size < 0 || payload_size > NETFRAME_MAX_PAYLOAD_SIZE)
    {
        return -6;
    }
    else if (crc1 != crc2)
    {
        return -7;
    }
    else if (crc1 != internal_crc16(payload, payload_size))
    {
        return -8;
    }
    else if (termination != 0xAAAA)
    {
        return -9;
    }

    return 1;
}

void NetFrame::print()
{
    dbprintlf("GUID ------------ 0x%08x", guid);
    dbprintlf("Type ------------ %d", (int)type);
    dbprintlf("Destination ----- %d", (int)destination);
    dbprintlf("Origin ---------- %d", (int)origin);
    dbprintlf("Payload Size ---- %ld", payload_size);
    dbprintlf("CRC1 ------------ 0x%04x", crc1);
    dbprintf("Payload ---- (HEX)");
    for (int i = 0; i < payload_size; i++)
    {
        printf(" 0x%04x", payload[i]);
    }
    printf("\n");
    dbprintlf("CRC2 ------------ 0x%04x", crc2);
    dbprintlf("NetStat --------- 0x%x", netstat);
    dbprintlf("Termination ----- 0x%04x", termination);
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
            NetFrame *polling_frame = new NetFrame(NULL, 0, NetType::POLL, NetVertex::SERVER);
            polling_frame->sendFrame(network_data);
            delete polling_frame;
        }
        else
        {
#ifdef GSNID
            // Disables automatic reconnection for the GUI Client and Server.
#ifndef XB_GS_TEST // Re-enables automatic reconnection for the xb_gs_test GUI client.
            if (strcmp(GSNID, "guiclient") != 0 && strcmp(GSNID, "server") != 0)
#endif
            {
                // Get our GS Network connection back up and running.
                gs_connect_to_server(network_data);
            }
#endif
#ifndef GSNID
            dbprintlf(FATAL "GSNID not defined. Please ensure one of the following exists:");
            dbprintlf(RED_FG "#define GSNID \"guiclient\"");
            dbprintlf(RED_FG "#define GSNID \"server\"");
            dbprintlf(RED_FG "#define GSNID \"roofuhf\"");
            dbprintlf(RED_FG "#define GSNID \"roofxband\"");
            dbprintlf(RED_FG "#define GSNID \"haystack\"");
            dbprintlf(RED_FG "#define GSNID \"track\"");
            dbprintlf(RED_FG "Or, in a Makefile: -DGSNID=\\\"guiclient\\\"");
#endif
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

    dbprintlf(BLUE_FG "Attempting connection to %s.", SERVER_IP);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    if ((network_data->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, SERVER_IP, &network_data->server_ip->sin_addr) <= 0)
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
        setsockopt(network_data->socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);

        network_data->connection_ready = true;
        connect_status = 1;
    }

    return connect_status;
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
                if (tout_s > 0)
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