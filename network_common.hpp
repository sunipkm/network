#include <stdint.h>

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