#include "network_common.hpp"
#include "sha_digest.hpp"

class NetClient : public NetData
{
public:
    ~NetClient();

    int client_id;
    struct sockaddr_in client_addr;
    int client_addrlen = sizeof(client_addr);

    friend class NetDataServer;
    friend class NetFrame;

    int MaxNumMissedPackets = 30; // Allow timeout on up to 10 RecvFrames before closing this connection

protected:
    NetDataServer *serv = nullptr;
};

class NetDataServer : public NetData
{
private:
    NetClient *clients = nullptr;
    int num_clients;
    int fd;
    bool listen_done = false;
    pthread_t accept_thread;

    friend void *gs_accept_thread(void *);
    friend int gs_accept(NetDataServer *, int);

    void _NetDataServer(NetPort listening_port, int clients);

public:
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
    const int GetNumClients() const { return num_clients; };
    const NetClient *GetClient(int id);
    /**
     * @brief Get the Client object referenced by vertex v (only top two bytes are considered)
     * 
     * @param v NetVertex
     * @return const NetClient* Pointer to the client or nullptr on failure
     */
    const NetClient *GetClient(NetVertex v);
};

typedef struct
{
    NetClient *src;  // source of the frame
    NetFrame *frame; // frame
    ssize_t *status; // status of the frame
} NetJobData;

void *gs_accept_thread(void *);