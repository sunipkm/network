/**
 * @file network_common.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.07.30
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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

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
#ifndef NETWORK_WINDOWS
    close(_socket);
    _socket = -1;
#else
    closesocket(_socket);
    _socket = INVALID_SOCKET;
#endif
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
        send_size = send(network_data->_socket, (char *)buffer, malloc_size, 0);

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
            sz = recv(network_data->_socket, (char *)header.bytes + offset, 1, MSG_WAITALL);
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
            sz = recv(network_data->_socket, (char *)header.bytes + offset, 1, MSG_WAITALL);
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
            sz = recv(network_data->_socket, (char *)this->payload + offset, 1, MSG_WAITALL);
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
            sz = recv(network_data->_socket, (char *)footer.bytes + offset, 1, MSG_WAITALL);
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