#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <string.h>
#include "sha_digest.hpp"

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

class NetData
{
public:
    int _socket = -1;                  // C Socket
    bool connection_ready = false;     // Connection Ready Indicator
    bool recv_active;                  // Receiving on this NetData
    int thread_status;                 // Status of thread
    NetVertex origin;                  // Vertex of this NetData instance
    bool ssl_ready = false;            // Indicates subsequent send/receives will follow SSL
    SSL *cssl = NULL;                  // SSL connection
    SSL_CTX *ctx = NULL;               // SSL context
    int MaxNumMissedPackets = 10;      // Allow timeout on up to 10 RecvFrames before closing this connection
    sha1_hash_t *auth_token = nullptr; // SHA hash authentication token

    pthread_t polling_thread = 0;                // ID of polling thread for this instance
    friend void *network_polling_thread(void *); // Polling thread function

    /**
     * @brief Get the Auth Token for this NetData object
     * 
     * @return const sha1_hash_t* 
     */
    const sha1_hash_t *GetAuthToken() const { return auth_token; };

    void Close();               // Close connection
    const bool const IsServer() // Is server or client
    {
        return server;
    };

    friend class NetDataServer; // Declared as friend as this constructor sets server to true

protected:
    NetData(){};

    void close_ssl_conn();

    bool server = false; // Server or Client
};

typedef union
{
    struct __attribute__((packed))
    {
        uint32_t guid; // Unique ID
        NetType type; // Frame Type (Network layer)
        FrameStatus status; // Frame Status (User layer)
        NetVertex origin; // Origin of frame
        NetVertex destination; // Destination of frame
        int32_t payload_size; // Size of payload
        int32_t payload_type; // Type of payload (User layer)
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
        memset(hdr, 0x0, sizeof(hdr));
        memset(ftr, 0x0, sizeof(ftr));
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
    NetFrame(void *payload, ssize_t size, int payload_type, NetType frame_type, NetVertex destination, FrameStatus status = FrameStatus::NONE);

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
    int RetrievePayload(void *storage, ssize_t capacity);

    /**
     * @brief Sends itself, frame must have been constructed using NetFrame(unsigned char *, ssize_t, NetType, NetVertex).
     * 
     * @return ssize_t Zero on success, negative on failure. 
     */
    ssize_t SendFrame(NetData *network_data);

    /**
     * @brief Receives data into a NetFrame constructed by NetFrame().
     * 
     * @param network_data Network Data struct 
     * @return ssize_t Number of bytes received on success, negative on failure.
     */
    virtual ssize_t RecvFrame(NetData *network_data);

    /**
     * @brief Checks the validity of itself.
     * 
     * @return int Positive if valid, negative if invalid.
     */
    int Validate();

    /**
     * @brief Prints the class' data.
     * 
     */
    void Print();

    // These exist because 'setting' is restrictive.
    NetType GetType() { return (NetType)hdr->type; };
    NetVertex GetOrigin() { return hdr->origin; };
    NetVertex GetDestination() { return hdr->destination; };
    FrameStatus GetStatus() { return hdr->status; };
    int GetPayloadSize() { return hdr->payload_size; };
    int GetPayloadType() { return hdr->payload_type; };
    /**
     * @brief Get the Frame Size of the NetFrame (applicable only for sendFrame())
     * 
     * @return ssize_t Frame size of sendFrame(), should be checked against the return value of sendFrame()
     */
    ssize_t GetFrameSize() { return frame_size; }

    friend class NetDataServer; // NetDataServer needs to access recvFrame(NetClient *)

private:
    // Sendable Data
    NetFrameHeader hdr[1];
    unsigned char *payload; // Dynamically sized payload, of capacity 0x100 to 0xfffe4 bytes.
    NetFrameFooter ftr[1];

    // Non-sendable Data (invisible to .sendFrame(...) and .recvFrame(...))
    ssize_t frame_size; // Set to the number of bytes that should have sent during the last .sendFrame(...).

    ssize_t RecvFrameInternal(NetData *network_data);
};

extern int ssl_lib_init;
void InitializeSSLLibrary();
void DestroySSLLibrary();