#include "network_server.hpp"
#include "meb_debug.hpp"
#include <openssl/err.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <new>
#include <stdexcept>

#define NETWORK_MAX_JOBS_SUPPORTED 500
#define NETWORK_JOB_MAX_ALLOWED_TIME 1000 // 1 seconds

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
};

class NetJobQueue
{
public:
    pthread_t jobthreads[NETWORK_MAX_JOBS_SUPPORTED];
    pthread_mutex_t joblocks[NETWORK_MAX_JOBS_SUPPORTED];
    NetJobData jobdata[NETWORK_MAX_JOBS_SUPPORTED];

    NetJobQueue();

    int AssignJob(NetJobData *jdata);
};

NetJobQueue::NetJobQueue()
{
    for (int i = 0; i < NETWORK_MAX_JOBS_SUPPORTED; i++)
    {
        jobthreads[i] = 0;
        joblocks[i] = PTHREAD_MUTEX_INITIALIZER;
        jobdata[i].frame = nullptr;
        jobdata[i].src = nullptr;
    }
}

void *server_job_handler(void *);

struct timespec WaitTime(int tout_ms) // timeout in milliseconds
{
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    tv.tv_sec += ({int tout_s = tout_ms / 1000; tout_ms -= tout_s * 1000; tout_s;});
    tv.tv_nsec += tout_ms * 1000000;
    if (tv.tv_nsec / 1000000000)
        tv.tv_sec += tv.tv_nsec / 1000000000;
    tv.tv_nsec = tv.tv_nsec % 1000000000;
    return tv;
}

int NetJobQueue::AssignJob(NetJobData *jdata)
{
    int ret = -1;

    if (jdata == nullptr || jdata == NULL)
        return ret;

    for (int i = 0; i < NETWORK_MAX_JOBS_SUPPORTED; i++ % NETWORK_MAX_JOBS_SUPPORTED)
    {
        if (pthread_mutex_trylock(&joblocks[i])) // successfully locked
        {
            struct timespec tv = WaitTime(NETWORK_JOB_MAX_ALLOWED_TIME);
            if (pthread_create(&jobthreads[i], NULL, server_job_handler, (void *)jdata))
            {
                pthread_mutex_unlock(&joblocks[i]);
                dbprintlf(RED_FG "Could not service job for client ID %d at loc %d", jdata->src->client_id, i);
                continue;
            }
            if (pthread_timedjoin_np(jobthreads[i], NULL, &tv) == ETIMEDOUT)
            {
                pthread_cancel(jobthreads[i]);
                ret = -ETIMEDOUT;
            }
            else
                ret = i;
            jobthreads[i] = 0;
            pthread_mutex_unlock(&joblocks[i]);
            break; // break out of the loop
        }
    }
    return ret;
}

NetJobQueue server_job_queue[1]; // New server job queue

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

NetDataServer::NetDataServer(NetPort listening_port, int clients, sha1_hash_t auth_token)
{
    this->auth_token = new sha1_hash_t();
    InitializeSSLLibrary();
    _NetDataServer(listening_port, clients);
    this->auth_token->copy(&auth_token);
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

NetDataServer::~NetDataServer()
{
    pthread_cancel(accept_thread);

    if (fd > 0)
    {
        close(fd);
        fd = -1;
    }

    for (int i = 0; i < num_clients; i++)
        if (clients[i].polling_thread != 0)
            pthread_cancel(clients[i].polling_thread); // kill the client polling threads

    if (clients != nullptr)
        delete[] clients;
    clients = nullptr;
    num_clients = 0;

    if (auth_token != nullptr)
        delete auth_token;
    auth_token = nullptr;
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

int gs_accept(NetDataServer *serv, int client_id)
{
    // check if client ID is valid
    if (client_id >= serv->num_clients)
    {
        dbprintlf("Invalid client ID, max clients %d", serv->num_clients);
        return -1;
    }
    // get local pointer to client referenced by ID
    NetClient *client = &(serv->clients[client_id]);
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
#ifdef __APPLE__
    // set socket option to not generate sigpipe if connection is broken
    setsockopt(client->_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif

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
        retval = frame->RecvFrame(client);
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
    if (frame->GetType() == NetType::SRV && frame->GetPayloadType() == SrvCmdTypes::SSL_AUTH_TOKEN && frame->GetStatus() == FrameStatus::NONE)
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
        else if (serv->GetAuthToken()->valid() != true)
        {
            dbprintlf(RED_FG "Authentication token not set up");
        }
        else if (frame->GetPayloadSize() != sizeof(sha1_hash_t))
        {
            dbprintlf(RED_FG "Authentication token size invalid");
        }
        else if (frame->RetrievePayload((void *) auth.GetBytes(), sizeof(auth)) < 0)
        {
            dbprintlf(RED_FG "Could not obtain authentication token\n");
        }
        else if (*serv->GetAuthToken() != auth)
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
        frame = new NetFrame((void *)vertices, sizeof(vertices), (int)SrvDataTypes::VERTEX_IDENT, NetType::SRV, vertices[0], ret);
    }
    else
    {
        frame = new NetFrame(NULL, 0, (int)SrvCmdTypes::SSL_AUTH_TOKEN, NetType::SRV, 0, ret);
        frame->SendFrame(client);
        delete frame;
        dbprintlf("Could not authenticate client");
        client->Close();
        return -1;
    }

    int bytes = frame->SendFrame(client);

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
        retval = frame->RecvFrame(client);
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
        dbprintlf(RED_FG "Expecting SRV, received %d", (int)frame->GetType());
    }
    else if (frame->GetPayloadType() != SrvCmdTypes::SET_CLIENT_VERTEX)
    {
        dbprintlf(RED_FG "Expecting SET_CLIENT_VERTEX, got %d", frame->GetPayloadType());
    }
    else if (frame->GetPayloadSize() != sizeof(NetVertex))
    {
        dbprintlf(RED_FG "Expecting payload size %d, got %d", sizeof(NetVertex), frame->GetPayloadSize());
    }
    else
    {
        // get the vertex payload
        NetVertex new_vertex = (NetVertex)0;
        frame->RetrievePayload(&new_vertex, sizeof(NetVertex));
        if ((new_vertex & 0xffff0000) == client->origin)
        {
            client->origin = new_vertex;
            ret = FrameStatus::ACK;
        }
    }
    delete frame;

    frame = new NetFrame((void *) &(client->origin), sizeof(NetVertex), (int)SrvCmdTypes::SET_CLIENT_VERTEX, NetType::SRV, client->origin, ret);
    frame->SendFrame(client);
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
    if (client->IsServer())
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
        client->Close();
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
        client->Close();
        return -4;
    }
    return 1;
}