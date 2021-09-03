#include <iostream>
#include "network_client.hpp"
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
    sha1_hash_t *auth_token = new sha1_hash_t("Hello world", 12);
    NetDataClient *conn = new NetDataClient("10.7.3.191", 52000, auth_token, 1000, 0x21, 0xfe);
    std::cout << "Connecting to server: " << conn->ConnectToServer() << std::endl;
    HANDLE poll_thread = INVALID_HANDLE_VALUE;
    std::cout << "Server vertex: " << std::hex << conn->GetServerVertex() << std::endl;
    std::cout << "Client vertex: " << conn->GetVertex() << std::dec << std::endl;
    Sleep(1000); // 1 second
    DWORD thread_id = 0;
    poll_thread = CreateThread(NULL, 0, gs_polling_thread, (LPVOID) conn, 0, &thread_id);
    if (poll_thread == INVALID_HANDLE_VALUE)
    {
        std::cout << "pthread_create failed" << std::endl;
        return -1;
    }
    while (!done)
        Sleep(1000);
    TerminateThread(poll_thread, thread_id);
    delete conn;
    return 0;
}
