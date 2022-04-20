/**
 * @file network_server.hpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Network Server API header
 * @version 0.1
 * @date 2021-09-10
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef NETWORK_SERVER_HPP
#define NETWORK_SERVER_HPP

#include <stdint.h>
#include "network_common.hpp"
#include <string.h>

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
    int fd = -1;
    bool listen_done = false;
#ifndef NETWORK_WINDOWS
    pthread_t accept_thread;
#else
    HANDLE accept_thread = INVALID_HANDLE_VALUE;
#endif
    sha1_hash_t *auth_token = nullptr;
    NetVertex origin = 0;
#ifndef NETWORK_WINDOWS
    friend void *gs_accept_thread(void *);
#else
    friend DWORD WINAPI gs_accept_thread(LPVOID);
#endif
    friend int gs_accept(NetDataServer *, int);

    void _NetDataServer(NetPort listening_port, int clients, const char *certname, const char *keyname);

public:
    /**
     * @brief Construct a new NetDataServer
     * 
     * @param listening_port Port to listen on
     * @param clients Maximum number of connections to be accepted
     * @param auth_token Authentication token to authenticate clients against
     */
    NetDataServer(NetPort listening_port, int clients, sha1_hash_t auth_token, const char *certname = NULL, const char *keyname = NULL);
    /**
     * @brief Destroy the NetDataServer object and close all active connections
     * 
     */
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
    /**
     * @brief Get the Client object for a given ID
     * 
     * @param id ID of the client [0 ... GetNumClients())
     * @return NetClient* Pointer to client, nullptr if not found
     */
    NetClient *GetClient(int id);
    /**
     * @brief Get the Client object for a given vertex
     * 
     * @param v NetVertex of the client
     * @return NetClient* Pointer to client, nullptr if not found
     */
    NetClient *GetClient(NetVertex v);
    /**
     * @brief Get the vertex for the server
     * 
     * @return const NetVertex 
     */
    const NetVertex GetVertex() const { return origin; };
    /**
     * @brief Get the authentication token the server was created with
     * 
     * @return const sha1_hash_t* 
     */
    const sha1_hash_t *GetAuthToken() const { return auth_token; };
};

#endif // NETWORK_SERVER_HPP