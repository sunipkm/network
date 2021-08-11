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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "network.hpp"
#include "meb_debug.hpp"

void network_data_init(network_data_t *network_data, int server_port)
{
    network_data->connection_ready = false;
    network_data->socket = -1;
    network_data->serv_ip->sin_family = AF_INET;
    network_data->serv_ip->sin_port = htons(server_port);
    strcpy(network_data->discon_reason, "N/A");   
}

NetworkFrame::NetworkFrame(NETWORK_FRAME_TYPE type, int payload_size)
{
    if (type < 0)
    {
        printf("NetworkFrame initialized with error type (%d).\n", (int)type);
        return;
    }

    if (payload_size > NETWORK_FRAME_MAX_PAYLOAD_SIZE)
    {
        printf("Cannot allocate payload larger than %d bytes.\n", NETWORK_FRAME_MAX_PAYLOAD_SIZE);
        return;
    }

    this->payload_size = payload_size;
    this->type = type;

    // TODO: Set the mode properly.
    mode = CS_MODE_ERROR;
    crc1 = -1;
    crc2 = -1;
    guid = NETWORK_FRAME_GUID;
    netstat = 0; // Will be set by the server.
    termination = 0xAAAA;

    memset(payload, 0x0, this->payload_size);
}

int NetworkFrame::storePayload(NETWORK_FRAME_ENDPOINT endpoint, void *data, int size)
{
    if (size > payload_size)
    {
        printf("Cannot store data of size larger than allocated payload size (%d > %d).\n", size, payload_size);
        return -1;
    }

    if (data == NULL)
    {
        dbprintlf("Prepping null packet.");
    }
    else
    {
        memcpy(payload, data, size);
    }

    crc1 = internal_crc16(payload, NETWORK_FRAME_MAX_PAYLOAD_SIZE);
    crc2 = internal_crc16(payload, NETWORK_FRAME_MAX_PAYLOAD_SIZE);

    this->endpoint = endpoint;

    // TODO: Placeholder until I figure out when / why to set mode to TX or RX.
    mode = CS_MODE_RX;

    return 1;
}

int NetworkFrame::retrievePayload(unsigned char *data_space, int size)
{
    if (size != payload_size)
    {
        printf("Data space size not equal to payload size (%d != %d).\n", size, payload_size);
        return -1;
    }

    memcpy(data_space, payload, payload_size);

    return 1;
}

int NetworkFrame::checkIntegrity()
{
    if (guid != NETWORK_FRAME_GUID)
    {
        return -1;
    }
    else if (endpoint < 0)
    {
        return -2;
    }
    else if (mode < 0)
    {
        return -3;
    }
    else if (payload_size < 0 || payload_size > NETWORK_FRAME_MAX_PAYLOAD_SIZE)
    {
        return -4;
    }
    else if (type < 0)
    {
        return -5;
    }
    else if (crc1 != crc2)
    {
        return -6;
    }
    else if (crc1 != internal_crc16(payload, NETWORK_FRAME_MAX_PAYLOAD_SIZE))
    {
        return -7;
    }
    else if (termination != 0xAAAA)
    {
        return -8;
    }

    return 1;
}

void NetworkFrame::print()
{
    printf("GUID ------------ 0x%04x\n", guid);
    printf("Endpoint -------- %d\n", endpoint);
    printf("Mode ------------ %d\n", mode);
    printf("Payload Size ---- %d\n", payload_size);
    printf("Type ------------ %d\n", type);
    printf("CRC1 ------------ 0x%04x\n", crc1);
    printf("Payload ---- (HEX)");
    for (int i = 0; i < payload_size; i++)
    {
        printf(" 0x%04x", payload[i]);
    }
    printf("\n");
    printf("CRC2 ------------ 0x%04x\n", crc2);
    printf("NetStat --------- 0x%x\n", netstat);
    printf("Termination ----- 0x%04x\n", termination);
}

ssize_t NetworkFrame::sendFrame(network_data_t *network_data)
{
    if (!(network_data->connection_ready))
    {
        dbprintlf(YELLOW_FG "Connection is not ready.");
        return -1;
    }

    if (network_data->socket < 0)
    {
        dbprintlf(RED_FG "Invalid socket (%d).", network_data->socket);
        return -1;
    }

    if (!checkIntegrity())
    {
        dbprintlf(YELLOW_FG "Integrity check failed, send aborted.");
        return -1;
    }

    printf("Sending the following (%d):\n", network_data->socket);
    print();

    return send(network_data->socket, this, sizeof(NetworkFrame), 0);
}

void *gs_polling_thread(void *args)
{
    dbprintlf(BLUE_FG "Beginning polling thread.");

    network_data_t *network_data = (network_data_t *)args;

    while (network_data->rx_active)
    {
        if (network_data->connection_ready)
        {
            NetworkFrame *null_frame = new NetworkFrame(CS_TYPE_NULL, 0x0);
            null_frame->storePayload(CS_ENDPOINT_SERVER, NULL, 0);
            null_frame->sendFrame(network_data);
            delete null_frame;
        }
        else
        {
            // Get our GS Network connection back up and running.
            gs_connect_to_server(network_data);
        }
        usleep(SERVER_POLL_RATE * 1000000);
    }

    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
    if (network_data->thread_status > 0)
    {
        network_data->thread_status = 0;
    }
    return nullptr;
}

int gs_network_transmit(network_data_t *network_data, NETWORK_FRAME_TYPE type, NETWORK_FRAME_ENDPOINT endpoint, void *data, int data_size)
{
    if (data_size < 0)
    {
        printf("Error: data_size is %d.\n", data_size);
        printf("Cancelling transmit.\n");
        return -1;
    }

    // Create a NetworkFrame to send our data in.
    NetworkFrame *clientserver_frame = new NetworkFrame(type, data_size);
    clientserver_frame->storePayload(endpoint, data, data_size);

    clientserver_frame->sendFrame(network_data);
    delete clientserver_frame;

    return 1;
}

int gs_connect_to_server(network_data_t *network_data)
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
    else if (inet_pton(AF_INET, SERVER_IP, &network_data->serv_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(network_data->socket, (struct sockaddr *)network_data->serv_ip, sizeof(network_data->serv_ip), 1) < 0)
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
