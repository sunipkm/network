#include <iostream>
#include "network.hpp"
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <meb_debug.hpp>

volatile sig_atomic_t done = 0;

void sighandler(int sig)
{
    done = 1;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sighandler);
    NetDataClient *conn = new NetDataClient("127.0.0.1", 52000, 1000);
    std::cout << "Connecting to server: " << gs_connect_to_server(conn) << std::endl;
    pthread_t poll_thread;
    std::cout << "Server vertex: " << conn->GetServerVertex() << std::endl;
    std::cout << "Client vertex: " << conn->GetVertex() << std::endl;
    conn->recv_active = true;
    NetFrame *frame = new NetFrame(NULL, 0, NetType::SSL_REQ, conn->GetServerVertex());
    frame->sendFrame(conn);
    delete frame;
    frame = new NetFrame();
    if (frame->recvFrame(conn) > 0)
    {
        dbprintlf("Received frame type: %d", (int)frame->getType());
        if (frame->getType() == NetType::ACK)
        {
            NetType req;
            frame->retrievePayload(&req, sizeof(NetType));
            if (req == NetType::SSL_REQ)
                conn->open_ssl_conn();
        }
    }
    if (pthread_create(&poll_thread, NULL, gs_polling_thread, conn) < 0)
    {
        std::cout << "pthread_create failed" << std::endl;
        return -1;
    }
    while (!done)
        sleep(1);
    pthread_cancel(poll_thread);
    delete conn;
    return 0;
}