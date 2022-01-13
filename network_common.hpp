/**
 * @file network_common.hpp
 * @author Mit Bailey (mitbailey99@gmail.com), Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Network Frames API
 * @version See Git tags for version information.
 * @date 2021.07.30
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef NETWORK_HPP
#define NETWORK_HPP

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define NETWORK_WINDOWS
#define _CRT_RAND_S
typedef int ssize_t;
#define WIN32_LEAN_AND_MEAN

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "crypt32")

#else
#include <arpa/inet.h>
#include <pthread.h>
#endif
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>

#define SERVER_POLL_RATE 5
#define RECV_TIMEOUT 15
#define NETFRAME_GUID 0x4d454239
#define NETFRAME_MIN_PAYLOAD_SIZE 0x100
#define NETFRAME_MAX_PAYLOAD_SIZE 0xfffe0
#define NETFRAME_TERMINATOR 0xa5a5

enum class NetType : int32_t
{
    POLL = 0x1a, // Poll connection
    DATA,        // data frame
    SRV,         // server connection acknowledgement frame
    AUTH,        // Authentication token
    MAX          // Last element
};

enum class FrameStatus : int32_t
{
    NONE = 0, // General frame
    ACK,      // Ack frame
    NACK,     // Nack frame
    MAX
};

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

typedef uint32_t NetVertex;

typedef int8_t ClientClass;
typedef uint8_t ClientID;

typedef uint16_t NetPort;

// class NetDataServer;

class NetData
{
public:
    int _socket = -1;
    bool connection_ready = false;
    bool conn_attempt = false;
    NetVertex origin;
    bool server = false;
    bool ssl_ready = false; // Indicates subsequent send/receives will follow SSL
    SSL *cssl = NULL;       // SSL connection
    SSL_CTX *ctx = NULL;    // SSL context
    ClientClass devclass;
    ClientID devId;

    void Close();
    void CloseSSLConn();

protected:
    NetData(){};
};

#ifdef NETWORK_WINDOWS
#pragma pack(1)
#endif
typedef union
{
#ifndef NETWORK_WINDOWS
    struct __attribute__((packed))
#else
    struct
#endif
    {
        uint32_t guid;
        int32_t type;
        int32_t status;
        uint32_t origin;
        uint32_t destination;
        int32_t payload_size;
        int32_t payload_type;
        uint16_t unused;
        uint16_t crc1;
    };
    uint8_t bytes[32];
} NetFrameHeader;

#ifdef NETWORK_WINDOWS
#pragma pack(1)
#endif
typedef union
{
#ifndef NETWORK_WINDOWS
    struct __attribute__((packed))
#else
    struct
#endif
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

    /**
     * @brief Construct a new NetFrame object
     * 
     * @param payload Pointer to data to send, can be NULL or nullptr if payload is of type POLL
     * @param size Size of payload (must be 0 if payload is NULL or nullptr)
     * @param payload_type Integer specifying type of payload (intended for endpoints)
     * @param type Frame type
     * @param status Frame status
     * @param destination Frame destination
     */
    NetFrame(void *payload, ssize_t size, int payload_type, NetType type, FrameStatus status, NetVertex destination);

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
     * @brief Send the network frame constructed using the NetFrame(unsigned char *, ssize_t, NetType, FrameStatus, NetVertex) constructor.
     * 
     * @param network_data Pointer to NetData inherited class
     * @param CloseOnFailure Close connection on failure
     * @return ssize_t Size of bytes sent on success, negative on failure
     */
    ssize_t sendFrame(NetData *network_data, bool CloseOnFailure = true);

    /**
     * @brief Receives data into a NetFrame constructed by NetFrame().
     * 
     * @param network_data Pointer to NetData inherited class
     * @param CloseOnFailure Close connection on failure
     * @return ssize_t Number of bytes received on success, negative on failure.
     */
    ssize_t recvFrame(NetData *network_data, bool CloseOnFailure = true);

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
    NetType getType() { return (NetType)hdr->type; };
    NetVertex getOrigin() { return hdr->origin; };
    NetVertex getDestination() { return hdr->destination; };
    int getPayloadSize() { return hdr->payload_size; };
    int getPayloadType() { return hdr->payload_type; };
    FrameStatus getStatus() { return (FrameStatus)hdr->status; };
    /**
     * @brief Get the Frame Size of the NetFrame (applicable only for sendFrame())
     * 
     * @return ssize_t Frame size of sendFrame(), should be checked against the return value of sendFrame()
     */
    ssize_t getFrameSize() { return frame_size; };

private:
    // Sendable Data
    NetFrameHeader hdr[1];
    unsigned char *payload; // Dynamically sized payload, of capacity 0x100 to 0xfffe4 bytes.
    NetFrameFooter ftr[1];

    // Non-sendable Data (invisible to .sendFrame(...) and .recvFrame(...))
    ssize_t frame_size; // Set to the number of bytes that should have sent during the last .sendFrame(...).
};

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

#ifdef NETWORK_WINDOWS
/**
 * @brief Sleep for t microseconds (rounded off to milliseconds, always larger)
 * 
 * @param t Microseconds to sleep for
 * @return 0
 */
static inline unsigned long usleep(__int64 usec) 
{ 
    HANDLE timer; 
    LARGE_INTEGER ft; 

    ft.QuadPart = -(10*usec); // Convert to 100 nanosecond interval, negative value indicates relative time

    timer = CreateWaitableTimer(NULL, TRUE, NULL); 
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
    WaitForSingleObject(timer, INFINITE); 
    CloseHandle(timer);
    return 0;
}
/**
 * @brief Sleep for t seconds
 * 
 * @param t Seconds to sleep for
 * @return 0
 */
static inline unsigned int sleep(unsigned int t)
{
    if (t == 0)
        return 0;
    unsigned int sleeptime = t * 1000;
    Sleep(sleeptime);
    return 0;
}

#define CLOCK_REALTIME 0
static int clock_gettime(int, struct timespec *spec)
{
    __int64 wintime; GetSystemTimeAsFileTime((FILETIME*)&wintime);
   wintime      -=116444736000000000i64;  //1jan1601 to 1jan1970
   spec->tv_sec  =wintime / 10000000i64;           //seconds
   spec->tv_nsec =wintime % 10000000i64 *100;      //nano-seconds
   return 0;
}
#endif

#endif // NETWORK_HPP
