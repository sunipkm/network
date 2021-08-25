/**
 * @file network.hpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.07.30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#define SERVER_POLL_RATE 5
#define RECV_TIMEOUT 15
#define NETFRAME_GUID 0x4d454239
#define NETFRAME_MIN_PAYLOAD_SIZE 0x100
#define NETFRAME_MAX_PAYLOAD_SIZE 0xfffe4
#define NETFRAME_TERMINATOR 0xa5a5

enum class NetType
{
    POLL = 0x1a, // Poll connection
    DATA,        // data frame
    SRV,         // server commands
    MAX          // Last element
};

enum class FrameStatus : uint16_t
{
    NONE = 0x0, // none
    ACK = 0x1,  // acknowledgement
    NACK = 0x2, // not-acknowledgement
    MAX
}

class sha1_hash_t
{
private:
    void clear()
    {
        memset(bytes, 0, sizeof(bytes));
    }

public:
    uint8_t bytes[SHA512_DIGEST_LENGTH];

    sha1_hash_t()
    {
        clear();
    }
    sha1_hash_t(const char *pass, size_t len)
    {
        if (pass != NULL && pass != nullptr)
        {
            SHA512_CTX ctx;
            SHA512_Init(&ctx);
            SHA512_Update(&ctx, pass, len);
            SHA512_Final(bytes, &ctx);
        }
    }
    void copy(uint8_t *src)
    {
        if ((src != NULL) && (src != nullptr))
            memcpy(bytes, src, sizeof(bytes));
    }
    int hash() const
    {
        int result = 0;
        for (int i = 0; i < sizeof(bytes); i++)
            result |= bytes[i];
        return result;
    }
    bool equal(sha1_hash_t hash) const
    {
        bool match = true;
        for (int i = 0; i < sizeof(bytes); i++)
        {
            match = bytes[i] == hash.bytes[i];
            if (!match)
                break;
        }
        return match;
    }
};

/**
 * @brief 4 bytes
 * For a client: 0x[Random vertex B1][Random vertex B0][Client Class (0x0 to 0x7f)][Client ID (0x0 to 0xff)]
 *                  (Set by server)    (Set by server)     (Declared by client)       (Declared by client)
 * 
 * For a server: 0x[Random vertex B3][Random vertex B2][Random vertex B1 (0x80 to 0xff)][Random vertex B0]
 * 
 */
typedef int32_t NetVertex;

/**
 * @brief Port number to which clients connect/servers listen on
 * 
 */
typedef uint16_t NetPort;

class NetDataServer;

class NetData
{
public:
    int _socket = -1;
    bool connection_ready = false;
    bool recv_active;
    int thread_status;
    NetVertex origin;

    void close_ssl_conn();

    friend class NetFrame;
    friend int gs_accept_ssl(NetData *);

protected:
    NetData(){};
    void Close();
    bool server = false;
    bool ssl_ready = false; // Indicates subsequent send/receives will follow SSL
    SSL *cssl = NULL;       // SSL connection
    SSL_CTX *ctx = NULL;    // SSL context
};

class NetDataClient : public NetData
{
private:
    char ip_addr[16];
    NetVertex server_vertex;
    struct sockaddr_in server_ip[1];
    char disconnect_reason[64];
    int polling_rate = 1000;
    int ConnectToServer();

    friend void *gs_polling_thread(void *);

public:
    NetDataClient(const char *ip_addr, NetPort server_port, int polling_rate);
    const char *GetIP() const { return ip_addr; }
    const char *GetDisconnectReason() const { return disconnect_reason; };
    NetVertex GetVertex() const { return origin; }
    NetVertex GetServerVertex() const { return server_vertex; }
    int GetPollingRate(){return polling_rate / 1000};
    int SetPollingRate(int);

    ~NetDataClient();
};

class NetClient : public NetData
{
public:
    ~NetClient();

    int client_id;
    struct sockaddr_in client_addr;
    int client_addrlen = sizeof(client_addr);

    friend class NetDataServer;
    friend class NetFrame;

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
    sha1_hash_t *auth_token = nullptr;

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
    int GetNumClients() { return num_clients; };
    NetClient *GetClient(int id);
    const sha1_hash_t *GetAuthToken() const { return auth_token; };
};

typedef union
{
    struct __attribute__((packed))
    {
        uint32_t guid;
        NetType type;
        FrameStatus status = 0;
        NetVertex origin;
        NetVertex destination;
        int32_t payload_size;
        int32_t payload_type; // implemented by client
        uint16_t crc1;
    };
    uint8_t bytes[28];
} NetFrameHeader;

typedef union
{
    struct __attribute__((packed))
    {
        uint16_t crc2;
        uint16_t termination;
    };
    uint8_t bytes[4];
} NetFrameFooter;

class NetFrame
{
public:
    /** CONSTRUCTOR
     * @brief Creates a NetFrame for receiving via .recvFrame(...).
     * 
     * Payload size set to negative one to indicate that in its current state, this NetFrame cannot be sent. 
     * 
     */
    NetFrame() : payload(nullptr)
    {
        hdr->payload_size = -1;
    }

    /** CONSTRUCTOR
     * @brief THROWS EXCEPTIONS. Creates a NetFrame for sending via .sendFrame(...).
     * 
     * @param payload 
     * @param size 
     * @param type 
     * @param dest 
     */
    NetFrame(void *payload, ssize_t size, int payload_type, NetVertex destination, FrameStatus status = FrameStatus::NONE);

    /** DESTRUCTOR
     * @brief Frees payload and zeroes payload size.
     * 
     */
    ~NetFrame();

    /**
     * @brief Copies payload to the passed space in memory.
     * 
     * @param storage Pointer to memory into which the payload is copied.
     * @param capacity The size of the memory space being passed.
     * @return int Positive on success, negative on failure.
     */
    int retrievePayload(void *storage, ssize_t capacity);

    /**
     * @brief Sends itself, frame must have been constructed using NetFrame(unsigned char *, ssize_t, NetType, NetVertex).
     * 
     * @return ssize_t Zero on success, negative on failure. 
     */
    ssize_t sendFrame(NetData *network_data);

    /**
     * @brief Receives data into a NetFrame constructed by NetFrame().
     * 
     * @param network_data Network Data struct 
     * @return ssize_t Number of bytes received on success, negative on failure.
     */
    ssize_t recvFrame(NetData *network_data);

    /**
     * @brief Checks the validity of itself.
     * 
     * @return int Positive if valid, negative if invalid.
     */
    int validate();

    /**
     * @brief Prints the class' data.
     * 
     */
    void print();

    // These exist because 'setting' is restrictive.
    NetType GetType() { return (NetType)hdr->type; };
    NetVertex GetOrigin() { return hdr->origin; };
    NetVertex GetDestination() { return hdr->destination; };
    FrameStatus GetStatus() {return hdr->status;};
    int GetPayloadSize() { return hdr->payload_size; };
    int GetPayloadType() { return hdr->payload_type; };
    /**
     * @brief Get the Frame Size of the NetFrame (applicable only for sendFrame())
     * 
     * @return ssize_t Frame size of sendFrame(), should be checked against the return value of sendFrame()
     */
    ssize_t getFrameSize() { return frame_size; }

    friend class NetDataServer; // NetDataServer needs to access recvFrame(NetClient *)

private:
    // Sendable Data
    NetFrameHeader hdr[1];
    unsigned char *payload; // Dynamically sized payload, of capacity 0x100 to 0xfffe4 bytes.
    NetFrameFooter ftr[1];

    // Non-sendable Data (invisible to .sendFrame(...) and .recvFrame(...))
    ssize_t frame_size; // Set to the number of bytes that should have sent during the last .sendFrame(...).

    // Server functions can only sendFrame depending on where the data came from, receive is done by the internal thread
    ssize_t recvFrame(NetClient *network_data);
};

/**
 * @brief Periodically polls the Ground Station Network Server for its status.
 * 
 * Doubles as the GS Network connection watch-dog, tries to restablish connection to the server if it sees that we are no longer connected.
 * 
 * @param args 
 * @return void* 
 */
void *gs_polling_thread(void *args);

void *gs_accept_thread(void *args);

/**
 * @brief 
 * 
 * From:
 * https://github.com/sunipkmukherjee/comic-mon/blob/master/guimain.cpp
 * with minor modifications.
 * 
 * @param socket 
 * @param address 
 * @param socket_size 
 * @param tout_s 
 * @return int 
 */
int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s);

/*
 * this is the CCITT CRC 16 polynomial X^16  + X^12  + X^5  + 1.
 * This works out to be 0x1021, but the way the algorithm works
 * lets us use 0x8408 (the reverse of the bit pattern).  The high
 * bit is always assumed to be set, thus we only use 16 bits to
 * represent the 17 bit value.
 */
static inline uint16_t internal_crc16(unsigned char *data_p, uint16_t length)
{
#define CRC16_POLY 0x8408
    unsigned char i;
    unsigned int data;
    unsigned int crc = 0xffff;

    if (length == 0)
        return (~crc);

    do
    {
        for (i = 0, data = (unsigned int)0xff & *data_p++;
             i < 8;
             i++, data >>= 1)
        {
            if ((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ CRC16_POLY;
            else
                crc >>= 1;
        }
    } while (--length);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);

    return (crc);
}

#endif // NETWORK_HPP
