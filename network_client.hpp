/**
 * @file network_client.hpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.09.02
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef NETWORK_CLIENT_HPP
#define NETWORK_CLIENT_HPP

#include "network_common.hpp"

#include <stdint.h>
#ifndef NETWORK_WINDOWS
#include <arpa/inet.h>
#include <pthread.h>
#endif
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <string.h>

class NetDataClient : public NetData
{
private:
    char ip_addr[16];
    NetVertex server_vertex;
    struct sockaddr_in server_ip[1];
    char disconnect_reason[64];
    int polling_rate = 5000; // POLL frame sent to the server every this-many milliseconds.
    sha1_hash_t *auth_token = nullptr;
    bool recv_active = false;

    int OpenSSLConn();
    void CloseSSLConn() {NetData *d = (NetData *) this; d->CloseSSLConn();};
    void Close() {NetData *d = (NetData *) this; d->Close();};

public:
    NetDataClient(const char *ip_addr, NetPort server_port, sha1_hash_t *auth, int polling_rate = 5000, ClientClass dclass = 0, ClientID did = 0);
    const char *GetIP() const { return ip_addr; }
    const char *GetDisconnectReason() const { return disconnect_reason; };
    NetVertex GetVertex() const { return origin; }
    NetVertex GetServerVertex() const { return server_vertex; }
    int GetPollingRate() const { return polling_rate / 1000; };
    int SetPollingRate(int prate)
    {
        prate *= 1000;
        if (prate < 1000)
            prate = 1000;
        else if (prate > 30000)
            prate = 30000;
        polling_rate = prate;
        return polling_rate / 1000;
    };
    void StopPolling() { recv_active = false; };

    ~NetDataClient();

    int ConnectToServer();
#ifndef NETWORK_WINDOWS
    friend void *gs_polling_thread(void *);
#else
    friend DWORD WINAPI gs_polling_thread(LPVOID);
#endif
};

/**
 * @brief Periodically polls the Ground Station Network Server for its status.
 * 
 * Doubles as the GS Network connection watch-dog, tries to restablish connection to the server if it sees that we are no longer connected.
 * 
 * @param args 
 * @return void* 
 */
#ifndef NETWORK_WINDOWS
void *gs_polling_thread(void *args);
#else
DWORD WINAPI gs_polling_thread(LPVOID args);
#endif

#endif // NETWORK_CLIENT_HPP