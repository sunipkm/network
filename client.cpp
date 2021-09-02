#include <iostream>
#include "network_client.hpp"
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
    signal(SIGPIPE, SIG_IGN);
    sha1_hash_t *auth_token = new sha1_hash_t("Hello world", 12);
    NetDataClient *conn = new NetDataClient("127.0.0.1", 52000, auth_token, 1000, 0x21, 0xfe);
    std::cout << "Connecting to server: " << conn->ConnectToServer() << std::endl;
    pthread_t poll_thread;
    std::cout << "Server vertex: " << std::hex << conn->GetServerVertex() << std::endl;
    std::cout << "Client vertex: " << conn->GetVertex() << std::dec << std::endl;
    sleep(1);
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
