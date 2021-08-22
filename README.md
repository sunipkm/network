# Network
Network interface around C sockets and OpenSSL in C++.

## Sending Data (Client)
```c
// Initialize a client's NetData object, giving the IP of the server, the port and polling rate in seconds.
NetDataClient *network_data = new NetDataClient("127.0.0.1", 52000, 1);

...

// Call the connect to server function, which sets the NetDataClient::socket and ::connection_ready values.
gs_connect_to_server(network_data);

...

// Create a data buffer, and fill it with some data.
unsigned char buffer[DATA_SIZE];

...

// Initialize a NetFrame object with data to send, set packet size appropriately and set destination to server vertex, send the frame, and clean up afterwards.
NetFrame *network_frame = new NetFrame(buffer, DATA_SIZE, NetType::DATA, network_data->GetServerVertex());
network_frame->sendFrame(network_data);
delete network_frame;
```
## Receiving Data (Client)
```c
NetDataClient *network_data = new NetDataClient("127.0.0.1", 52000, 1);

...

gs_connect_to_server(network_data);

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
## Sending Data (Server)
```c
// Initialize a server's NetData object, giving the port to listen on and how many active connections to expect.
NetDataServer *network_data = new NetDataServer(52000, 5);

...

// Create a data buffer, and fill it with the payload.
unsigned char buffer[DATA_SIZE];

...

// Initialize a NetFrame object, set destination to specific client ID, send the frame, and clean up afterwards.
NetFrame *network_frame = new NetFrame(buffer, DATA_SIZE, NetType::DATA, network_data->GetClient(id));
network_frame->sendFrame(network_data);
delete network_frame;
```
## Receiving Data (Server)
```c
NetDataServer *network_data = new NetDataServer(52000, 5);

...

// Construct a NetFrame object for receiving into, and call the receiving function.
NetFrame *network_frame = new NetFrame();
network_frame->recvFrame(network_data);

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
    ACK,         // acknowledge last transmission
    NACK,        // not-acknowledge last transmission
    DATA,        // data frame
    CMD,         // command frame
    SRV,         // server connection acknowledgement frame
    SSL_REQ,     // request for SSL connection
};
```
## NetVertex
_A point within the network._