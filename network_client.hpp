#include "network_common.hpp"
#include "sha_digest.hpp"

#define RECV_TIMEOUT 10 // receive timeout in seconds

class NetDataClient : public NetData
{
private:
    char ip_addr[16];
    NetVertex server_vertex;
    struct sockaddr_in server_ip[1];
    char disconnect_reason[64];
    int polling_rate = 1000;
    int ConnectToServer();
    int open_ssl_conn();
    char client_class = 0;
    uint8_t client_type = 1;

    friend void *network_client_polling_thread(void *);
    friend int network_client_connect_to_server(NetDataClient *);

public:
    NetDataClient(const char *ip_addr, NetPort server_port, char client_class = 0, uint8_t client_type = 1);
    const char *GetIP() const { return ip_addr; }
    const char *GetDisconnectReason() const { return disconnect_reason; };
    NetVertex GetVertex() const { return origin; }
    NetVertex GetServerVertex() const { return server_vertex; }
    const int GetPollingRate() const { return polling_rate / 1000; };
    int SetPollingRate(int);

    ~NetDataClient();
};

typedef struct
{
    NetData *src;    // source of the frame
    NetFrame *frame; // frame
} NetJobData;

int network_client_connect_to_server(NetDataClient *);