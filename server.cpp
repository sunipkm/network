#include <iostream>
#include "network.hpp"
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include "meb_debug.hpp"

volatile sig_atomic_t done = 0;

void sighandler(int sig)
{
    done = 1;
}

int main(int argc, char *argv[])
{
    NetDataServer *server = new NetDataServer(52000, 5);
    signal(SIGINT, sighandler);
    while (!done)
    {
        for (int i = 0; i < server->GetNumClients(); i++)
        {
            NetFrame *frame = new NetFrame();
            int rcv_val = 0;
            if (server->GetClient(i)->connection_ready)
                rcv_val = frame->recvFrame(server->GetClient(i));
            if (rcv_val)
            {
                std::cout << "Frame received from client ID " << i << ", vertex " << (int)frame->getOrigin() << ", frame type " << (int)frame->getType() << std::endl;
            }
            delete frame;
        }
        std::cout << std::endl;
        sleep(1);
    }
    return 0;
}