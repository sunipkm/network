/**
 * @file network_server.hpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.09.02
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef NETWORK_SERVER_HPP
#define NETWORK_SERVER_HPP

#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <string.h>
#include "network_common.hpp"

class NetDataServer;

class NetClient : public NetData
{
public:
    ~NetClient();

    int client_id;
    struct sockaddr_in client_addr;
    int client_addrlen = sizeof(client_addr);

    friend class NetDataServer;

protected:
    NetDataServer *serv = nullptr;
};

class NetDataServer
{
private:
    NetClient *clients = nullptr;
    int num_clients;
    int fd;
    bool listen_done = false;
    pthread_t accept_thread;
    sha1_hash_t *auth_token = nullptr;
    NetVertex origin = 0;

    friend void *gs_accept_thread(void *);
    friend int gs_accept(NetDataServer *, int);

    void _NetDataServer(NetPort listening_port, int clients);

public:
    NetDataServer(NetPort listening_port, int clients);
    NetDataServer(NetPort listening_port, int clients, sha1_hash_t auth_token);
    ~NetDataServer();
    /**
     * @brief Stop accepting new connections
     * 
     */
    void StopAccept() { listen_done = true; };
    /**
     * @brief Get the number of clients supported
     * @return int 
     */
    int GetNumClients() { return num_clients; };
    NetClient *GetClient(int id);
    NetClient *GetClient(NetVertex v);
    int open_ssl_conn();
    const sha1_hash_t *GetAuthToken() const { return auth_token; };
};

#endif // NETWORK_SERVER_HPP