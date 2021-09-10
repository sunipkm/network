/**
 * @file network_client.hpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Network Client API Header
 * @version 1.0
 * @date 2021-09-10
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
    /**
     * @brief Construct a new NetDataClient object
     * 
     * @param ip_addr IP address of server (if NULL or nullptr, 127.0.0.1 is used). Does NOT provide DNS services.
     * @param server_port Port on server to connect to.
     * @param auth sha1_hash_t object used for authentication
     * @param polling_rate Rate at which connection to the server is polled
     * @param dclass Device class, integer between 0 and 127. Intended to provide methods for easy communication between clients.
     * @param did Device ID, ID of device in the same class of devices.
     */
    NetDataClient(const char *ip_addr, NetPort server_port, sha1_hash_t *auth, int polling_rate = 5000, ClientClass dclass = 0, ClientID did = 0);
    /**
     * @brief Get IP address of connected device.
     * 
     * @return const char* Pointer to IP address
     */
    const char *GetIP() const { return ip_addr; }
    /**
     * @brief Get the Disconnect Reason string
     * 
     * @return const char* 
     */
    const char *GetDisconnectReason() const { return disconnect_reason; };
    /**
     * @brief Get the assigned vertex of the NetDataClient
     * 
     * @return NetVertex 
     */
    NetVertex GetVertex() const { return origin; }
    /**
     * @brief Get the vertex of the server
     * 
     * @return NetVertex 
     */
    NetVertex GetServerVertex() const { return server_vertex; }
    /**
     * @brief Get the server polling rate
     * 
     * @return int Polling rate in seconds
     */
    int GetPollingRate() const { return polling_rate / 1000; };
    /**
     * @brief Set the server polling rate
     * 
     * @param prate Polling rate in seconds 
     * @return int Polling rate in seconds (set)
     */
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
    /**
     * @brief Disable polling
     * 
     */
    void StopPolling() { recv_active = false; };

    ~NetDataClient();
    /**
     * @brief Connect to server manually.
     * 
     * @return int Positive on success, negative on error
     */
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