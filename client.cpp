#include <iostream>
#include "network_client.hpp"
#ifndef NETWORK_WINDOWS
#include <pthread.h>
#include <unistd.h>
#endif
#include <signal.h>
#include <meb_debug.hpp>

volatile sig_atomic_t done = 0;

void sighandler(int sig)
{
    done = 1;
}

static char IP_ADDR[16] = "127.0.0.1";

int main(int argc, char *argv[])
{
    char *ip_addr = IP_ADDR;
    if (argc == 2)
        ip_addr = argv[1];
    signal(SIGINT, sighandler);
#ifndef NETWORK_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#endif
    sha1_hash_t *auth_token = new sha1_hash_t("Hello world", 12);
    NetDataClient *conn = new NetDataClient(ip_addr, 52000, auth_token, 1000, 0x21, 0xfe);
    std::cout << "Connecting to server: " << conn->ConnectToServer() << std::endl;
    std::cout << "Server vertex: " << std::hex << conn->GetServerVertex() << std::endl;
    std::cout << "Client vertex: " << conn->GetVertex() << std::dec << std::endl;
    sleep(1);
#ifndef NETWORK_WINDOWS
    pthread_t poll_thread;
    if (pthread_create(&poll_thread, NULL, gs_polling_thread, conn) < 0)
#else
    HANDLE poll_thread;
    DWORD status = 0;
    poll_thread = CreateThread(0, 0, gs_polling_thread, conn, 0, &status);
    if (poll_thread == INVALID_HANDLE_VALUE)
#endif
    {
        std::cout << "pthread_create failed" << std::endl;
        return -1;
    }
    while (!done)
    {
        sleep(1);
    }
#ifndef NETWORK_WINDOWS
    pthread_cancel(poll_thread);
#else
    TerminateThread(poll_thread, status);
#endif
    delete conn;
    return 0;
}
