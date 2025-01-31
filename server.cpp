/**
 * @file server.cpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Platform independent example server
 * @version 1.0
 * @date 2021-09-10
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include <iostream>
#include "network_server.hpp"
#ifndef NETWORK_WINDOWS
#include <unistd.h>
#endif
#include <signal.h>
#include "meb_print.h"

volatile sig_atomic_t done = 0;

void sighandler(int sig)
{
    done = 1;
}

int main(int argc, char *argv[])
{
    sha1_hash_t passwd = sha1_hash_t("Hello world", 12);
    NetDataServer *server = new NetDataServer(52000, 100, passwd);
    signal(SIGINT, sighandler);
#ifndef NETWORK_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#endif
    while (!done)
    {
        // for (int i = 0; i < server->GetNumClients(); i++)
        // {
        //     NetFrame *frame = new NetFrame();
        //     int rcv_val = 0;
        //     if (server->GetClient(i)->ssl_ready)
        //         rcv_val = frame->recvFrame(server->GetClient(i));
        //     if (rcv_val > 0) // conn closed
        //     {
        //         std::cout << "Frame received " << rcv_val << " from client ID " << i << ", vertex " << std::hex << (int)frame->getOrigin() << std::dec << ", frame type " << (int)frame->getType() << std::endl;
        //     }
        //     delete frame;
        // }
        sleep(1);
    }
    delete server;
    return 0;
}