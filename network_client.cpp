#include "network_common.hpp"
#include "network_client.hpp"
#include "meb_debug.hpp"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

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

void *network_client_polling_thread(void *args)
{
    dbprintlf(BLUE_FG "Beginning polling thread.");

    NetDataClient *network_data = (NetDataClient *)args;

    while (network_data->recv_active)
    {
        if (network_data->connection_ready)
        {
            NetFrame *polling_frame = new NetFrame(NULL, 0, 0, NetType::POLL, network_data->server_vertex);
            polling_frame->SendFrame(network_data);
            polling_frame->Print();
            delete polling_frame;
        }
        else
        {
            dbprintlf("Connect to server from poll\n");
            network_client_connect_to_server(network_data);
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

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, char client_class = 0, uint8_t client_type = 1)
{
    ctx = InitializeSSLClient();
    if (ip_addr == NULL)
        strcpy(this->ip_addr, "127.0.0.1");
    else
    {
        strncpy(this->ip_addr, ip_addr, sizeof(this->ip_addr));
    }
    strcpy(disconnect_reason, "N/A");
    server_ip->sin_family = AF_INET;
    server_ip->sin_port = htons((int)server_port);
    this->client_class = client_class;
    this->client_type = client_type;
    this->polling_thread = 0;

    // TODO: start the polling thread, and this will automatically open the connection
}

int network_client_connect_to_server(NetDataClient *network_data)
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
#ifndef __linux__
        setsockopt(network_data->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
        // Receive server acknowledgement
        NetFrame *frame = new NetFrame();
        NetDataClient *_network_data = (NetDataClient *)malloc(sizeof(NetDataClient));
        memcpy(_network_data, network_data, sizeof(NetDataClient));
        _network_data->connection_ready = true;
        if ((connect_status = frame->RecvFrame(_network_data)) <= 0)
        {
            dbprintlf("Server did not reply with end point number assignment");
            connect_status = -4;
        }
        else if (frame->GetType() != NetType::SRV)
        {
            dbprintlf("Server did not reply with an SRV type packet, reply type %d", frame->GetType());
            connect_status = -5;
        }
        else if (frame->GetPayloadSize() != 2 * sizeof(NetVertex))
        {
            dbprintlf("Server reply payload size mismatch");
            frame->Print();
            connect_status = -6;
        }
        else
        {
            NetVertex vertices[2];
            frame->RetrievePayload(vertices, 2 * sizeof(NetVertex));
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
        NetFrame *frame;
        // TODO: Set up SSL connection here
        // NetFrame *frame = new NetFrame(&acktype, sizeof(NetType), NetType::ACK, network_data->server_vertex);
        int retval;
        if ((retval = frame->SendFrame(network_data)) < 0)
        {
            dbprintlf("Could not send ACK frame, error %d", retval);
            return retval;
        }
        delete frame;
    }
    network_data->recv_active = true;
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