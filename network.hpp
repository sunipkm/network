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

#define SERVER_POLL_RATE 5
#define RECV_TIMEOUT 15
#define NETWORK_FRAME_GUID 0x1A1C
#define NETWORK_FRAME_MAX_PAYLOAD_SIZE 0x100
#define SERVER_IP "127.0.0.1" // hostname -I

/**
 * @brief X-Band configuration status information to be filled by the radios, sent to the server, and then to the client.
 * 
 */
typedef struct
{
    int mode;               // 0:SLEEP, 1:FDD, 2:TDD
    int pll_freq;           // PLL Frequency
    uint64_t LO;            // LO freq
    uint64_t samp;          // sampling rate
    uint64_t bw;            // bandwidth
    char ftr_name[64];      // filter name
    int temp;               // temperature
    double rssi;            // RSSI
    double gain;            // TX Gain
    char curr_gainmode[16]; // fast_attack or slow_attack
    bool pll_lock;
} phy_config_t;

enum NETWORK_FRAME_TYPE
{
    CS_TYPE_ERROR = -1,       // Something is wrong.
    CS_TYPE_NULL = 0,         // Blank, used for holding open the socket and retrieving status data.
    CS_TYPE_ACK = 1,          // Good acknowledgement.
    CS_TYPE_NACK = 2,         // Bad acknowledgement.
    CS_TYPE_CONFIG_UHF = 3,   // Configure UHF radio.
    CS_TYPE_CONFIG_XBAND = 4, // Configure X-Band radio.
    CS_TYPE_DATA = 5,         // Most communications will be _DATA.
};

enum NETWORK_FRAME_ENDPOINT
{
    CS_ENDPOINT_ERROR = -1,
    CS_ENDPOINT_CLIENT = 0,
    CS_ENDPOINT_ROOFUHF,
    CS_ENDPOINT_ROOFXBAND,
    CS_ENDPOINT_HAYSTACK,
    CS_ENDPOINT_SERVER
};

enum NETWORK_FRAME_MODE
{
    CS_MODE_ERROR = -1,
    CS_MODE_RX = 0,
    CS_MODE_TX = 1
};

typedef struct
{
    // Network
    int server_poll_rate;
    int socket;
    struct sockaddr_in serv_ip[1];
    bool connection_ready;
    char discon_reason[64];

    // Booleans
    bool rx_active; // Only able to receive when this is true.  

    int thread_status; 
} network_data_t;

void network_data_init(network_data_t *network_data, int server_port);

class NetworkFrame
{
public:
    /**
     * @brief Sets the payload_size, type, GUID, and termination values.
     * 
     * @param payload_size The desired payload size.
     * @param type The type of data this frame will carry (see: NETWORK_FRAME_TYPE).
     */
    NetworkFrame(NETWORK_FRAME_TYPE type, int payload_size);

    /**
     * @brief Copies data to the payload.
     * 
     * Returns and error if the passed data size does not equal the internal payload_size variable set during class construction.
     * 
     * Sets the CRC16s.
     * 
     * @param endpoint The final destination for the payload (see: NETWORK_FRAME_ENDPOINT).
     * @param data Data to be copied into the payload.
     * @param size Size of the data to be copied.
     * @return int Positive on success, negative on failure.
     */
    int storePayload(NETWORK_FRAME_ENDPOINT endpoint, void *data, int size);

    /**
     * @brief Copies payload to the passed space in memory.
     * 
     * @param data_space Pointer to memory into which the payload is copied.
     * @param size The size of the memory space being passed.
     * @return int Positive on success, negative on failure.
     */
    int retrievePayload(unsigned char *data_space, int size);

    int getPayloadSize() { return payload_size; };

    NETWORK_FRAME_TYPE getType() { return type; };

    NETWORK_FRAME_ENDPOINT getEndpoint() { return endpoint; };

    uint8_t getNetstat() { return netstat; };

    /**
     * @brief Checks the validity of itself.
     * 
     * @return int Positive if valid, negative if invalid.
     */
    int checkIntegrity();

    /**
     * @brief Prints the class' data.
     * 
     */
    void print();

    /**
     * @brief Sends itself using the network data passed to it.
     * 
     * @return ssize_t Number of bytes sent if successful, negative on failure. 
     */
    ssize_t sendFrame(network_data_t *network_data);

    phy_config_t roofxband_config_status[1];
    phy_config_t haystack_config_status[1];

private:
    uint16_t guid;                                         // 0x1A1C
    NETWORK_FRAME_ENDPOINT endpoint;                       // Where is this going?
    NETWORK_FRAME_MODE mode;                               // RX or TX
    int payload_size;                                      // Variably sized payload, this value tracks the size.
    NETWORK_FRAME_TYPE type;                               // NULL, ACK, NACK, CONFIG, DATA, STATUS
    uint16_t crc1;                                         // CRC16 of payload.
    unsigned char payload[NETWORK_FRAME_MAX_PAYLOAD_SIZE]; // Constant sized payload.
    uint16_t crc2;
    uint8_t netstat;      // Network Status Information - Read by the client, set by the server: Bitmask - 0:Client, 1:RoofUHF, 2: RoofXB, 3: Haystack
    uint16_t termination; // 0xAAAA
};

/**
 * @brief Packs data into a NetworkFrame and sends it.
 * 
 * @param network_data 
 * @param type 
 * @param endpoint 
 * @param data 
 * @param data_size 
 * @return int 
 */
int gs_network_transmit(network_data_t *network_data, NETWORK_FRAME_TYPE type, NETWORK_FRAME_ENDPOINT endpoint, void *data, int data_size);

/**
 * @brief 
 * 
 * @param network_data 
 * @return int 
 */
int gs_connect_to_server(network_data_t *network_data);

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
