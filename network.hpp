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

#define SERVER_POLL_RATE 5
#define RECV_TIMEOUT 15
#define NETFRAME_GUID 0x4d454239
#define NETFRAME_MIN_PAYLOAD_SIZE 0x100
#define NETFRAME_MAX_PAYLOAD_SIZE 0xfffe4
#define NETFRAME_TERMINATOR 0xa5a5

enum class NetType
{
    POLL = 0x1a, // Poll connectoion
    ACK,         // acknowledge last transmission
    NACK,        // not-acknowledge last transmission
    DATA,        // data frame
    CMD,         // command frame
    SRV,         // server connection acknowledgement frame
    MAX          // Last element
};

typedef int32_t NetVertex;

typedef uint16_t NetPort;

class NetData
{
public:
    int _socket = -1;
    bool connection_ready = false;
    bool recv_active;
    int thread_status;
    NetVertex origin;

    friend class NetFrame;

protected:
    NetData() {};
    void Close();
};

class NetDataClient : public NetData
{
private:
    char ip_addr[16];
    NetVertex server_vertex;
    struct sockaddr_in server_ip[1];
    char disconnect_reason[64];
public:
    NetDataClient(const char *ip_addr, NetPort server_port, int polling_rate);
    const char *GetIP() const {return ip_addr;}
    const char *GetDisconnectReason() const {return disconnect_reason;};
    NetVertex GetVertex() const {return origin;}
    NetVertex GetServerVertex() const {return server_vertex;}

    friend int gs_connect_to_server(NetDataClient *network_data);
    friend void *gs_polling_thread(void *);

public:
    int polling_rate = 1000; // POLL frame sent to the server every this-many milliseconds.
};

class NetClient : public NetData
{
public:
    int client_id;
    struct sockaddr_in client_addr;
    int client_addrlen = sizeof(client_addr);
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
public:
    NetDataServer(NetPort listening_port, int clients);
    ~NetDataServer();
    /**
     * @brief Stop accepting new connections
     * 
     */
    void StopAccept() {listen_done = true;};
    /**
     * @brief Get the number of clients supported
     * @return int 
     */
    int GetNumClients() {return num_clients;};
    NetClient *GetClient(int id);

    friend int gs_accept(NetDataServer *, int);
};

typedef union
{
    struct __attribute__((packed))
    {
        uint32_t guid;
        int32_t type;
        int32_t origin;
        int32_t destination;
        int32_t payload_size;
        uint16_t crc1;
    };
    uint8_t bytes[22];
} NetFrameHeader;

typedef union
{
    struct __attribute__((packed))
    {
        uint16_t crc2;
        uint8_t netstat;
        uint16_t termination;
    };
    uint8_t bytes[5];
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
    NetFrame(void *payload, ssize_t size, NetType type, NetVertex destination);

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

    /**
     * @brief Print network status.
     * 
     */
    void printNetstat();

    // This exists because 'setting' is restrictive.
    int setNetstat(uint8_t netstat);

    // These exist because 'setting' is restrictive.
    NetType getType() { return (NetType)hdr->type; };
    NetVertex getOrigin() { return hdr->origin; };
    NetVertex getDestination() { return hdr->destination; };
    int getPayloadSize() { return hdr->payload_size; };
    /**
     * @brief Get the Frame Size of the NetFrame (applicable only for sendFrame())
     * 
     * @return ssize_t Frame size of sendFrame(), should be checked against the return value of sendFrame()
     */
    ssize_t getFrameSize() { return frame_size; }
    uint8_t getNetstat() { return ftr->netstat; };

private:
    // Sendable Data
    NetFrameHeader hdr[1];
    unsigned char *payload; // Dynamically sized payload, of capacity 0x100 to 0xfffe4 bytes.
    NetFrameFooter ftr[1];

    // Non-sendable Data (invisible to .sendFrame(...) and .recvFrame(...))
    ssize_t frame_size; // Set to the number of bytes that should have sent during the last .sendFrame(...).
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
 * @param network_data 
 * @return int 
 */
int gs_connect_to_server(NetDataClient *network_data);

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
