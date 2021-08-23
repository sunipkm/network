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
    sha1_hash_t passwd = sha1_hash_t("Hello worle", 12);
    NetDataServer *server = new NetDataServer(52000, 5, passwd);
    signal(SIGINT, sighandler);
    while (!done)
    {
        for (int i = 0; i < server->GetNumClients(); i++)
        {
            NetFrame *frame = new NetFrame();
            int rcv_val = 0;
            if (server->GetClient(i)->connection_ready)
                rcv_val = frame->recvFrame(server->GetClient(i));
            if (rcv_val > 0) // conn closed
            {
                std::cout << "Frame received " << rcv_val << " from client ID " << i << ", vertex " << (int)frame->getOrigin() << ", frame type " << (int)frame->getType() << std::endl;
            }
            delete frame;
        }
        sleep(1);
    }
    delete server;
    return 0;
}