# Network
Network interface around C sockets and OpenSSL in C++.

## Generate Authentication Token
```c
sha1_hash_t *auth_token = new sha1_hash_t("Hello world", 12);
```
Note: Ideally, the authentication token should be generated and saved in a file, that can be read. Generating the token in binary where the password string might remain stored may not be intended.

## Open a connection to a server
```c
// Initialize a client's NetData object, giving the IP of the server, the port and polling rate in seconds.
NetDataClient *network_data = new NetDataClient("127.0.0.1", 52000, , auth_token, 1); 

...

network_data->ConnectToServer();
```
// Call the connect to server function, which sets the NetDataClient::socket and ::connection_ready values.

## Sending Data (Client)
```c
...
// Create a data buffer, and fill it with some data.
unsigned char buffer[DATA_SIZE];

...

// Initialize a NetFrame object with data to send, set packet size appropriately and set destination to server vertex, send the frame, and clean up afterwards.
NetFrame *network_frame = new NetFrame(buffer, DATA_SIZE, 0, NetType::DATA, FrameStatus::NONE, network_data->GetServerVertex());
network_frame->sendFrame(network_data);
delete network_frame;
```
## Receiving Data (Client)
```c

...

// Construct a NetFrame object for receiving into, and call the receiving function.
NetFrame *network_frame = new NetFrame();
network_frame->recvFrame(network_data);

// Allocate a buffer of appropriate size to hold the payload, and call retrievePayload to fill it.
ssize_t buffer_size = network_frame->getPayloadSize();
unsigned char *buffer = (unsigned char *)malloc(buffer_size);
network_frame->retrievePayload(buffer, buffer_size);

...

free(buffer);
```
## Create a server
```c
// Initialize a server's NetData object, giving the port to listen on and how many active connections to expect.
NetDataServer *network_data = new NetDataServer(52000, 5, auth_token);
```
## Sending Data (Server)
```c

// Create a data buffer, and fill it with the payload.
unsigned char buffer[DATA_SIZE];

...

// Initialize a NetFrame object, set destination to specific client ID, send the frame, and clean up afterwards.
NetFrame *network_frame = new NetFrame(buffer, DATA_SIZE, 0, NetType::DATA, FrameStatus::NONE, network_data->GetVertex(0)); // to client ID 0
network_frame->sendFrame(network_data);
delete network_frame;
```
## Receiving Data (Server)
```c

...

// Construct a NetFrame object for receiving into, and call the receiving function.
NetFrame *network_frame = new NetFrame();
network_frame->recvFrame(network_data->GetClient(0)); // from client ID 0

// Allocate a buffer of appropriate size to hold the payload, and call retrievePayload to fill it.
ssize_t buffer_size = network_frame->getPayloadSize();
unsigned char *buffer = (unsigned char *)malloc(buffer_size);
network_frame->retrievePayload(buffer, buffer_size);
```
## NetType
_Generic packet types._
```c
enum class NetType
{
    POLL = 0x1a, // Poll connection
    DATA,        // data frame
    SRV,         // Server related frame
    AUTH,        // Authentication Token
};
```
## NetVertex
_A point within the network._

## Win32 Port
Requires installation of OpenSSL binaries. Pre-compiled binaries are provided with v1.0 release.