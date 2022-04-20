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
#include <sys/time.h>
#endif
#include <signal.h>
#include <inttypes.h>
#include "meb_print.hpp"

// #define BUFFER_SZ 2048

volatile sig_atomic_t done = 0;

void sighandler(int sig)
{
    done = 1;
}

int timeval_subtract(
    struct timespec *result, struct timespec *x, struct timespec *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_nsec < y->tv_nsec)
    {
        long long int nsec = (y->tv_nsec - x->tv_nsec) / 1000000000LL + 1;
        y->tv_nsec -= 1000000000LL * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_nsec - y->tv_nsec > 1000000000LL)
    {
        long long int nsec = (x->tv_nsec - y->tv_nsec) / 1000000000LL;
        y->tv_nsec += 1000000000LL * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_nsec = x->tv_nsec - y->tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

int main(int argc, char *argv[])
{
    sha1_hash_t passwd = sha1_hash_t("Hello world", 12);
    NetDataServer *server = new NetDataServer(52000, 1, passwd);
    signal(SIGINT, sighandler);
#ifndef NETWORK_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#endif

    // timespec avg[1];
    double avg_sec = 0.0;
    double avg_nsec = 0.0;
    bool fresh_run = true;
    long N = 0;

    uint8_t *buf = new uint8_t[NETFRAME_MAX_PAYLOAD_SIZE];
    while (!done)
    {
        for (int i = 0; i < server->GetNumClients(); i++)
        {

            static struct timespec tm[1];
            static struct timespec tm1[1];
            NetFrame *frame = new NetFrame();
            int rcv_val = 0;
            if (server->GetClient(i)->connection_ready)
                rcv_val = frame->recvFrame(server->GetClient(i));
            if (rcv_val > 0) // conn closed
            {
                if (frame->getType() == NetType::POLL)
                    std::cout << "Frame received " << rcv_val << " from client ID " << i << ", vertex " << std::hex << (int)frame->getOrigin() << std::dec << ", frame type " << (int)frame->getType() << std::endl;
                else
                {
                    clock_gettime(CLOCK_REALTIME, tm);
                    frame->retrievePayload(buf, NETFRAME_MAX_PAYLOAD_SIZE);
                    memcpy(tm1, buf, sizeof(struct timespec));
                    struct timespec diff[1];
                    timeval_subtract(diff, tm, tm1);
                    printf("Diff: %" PRId64 " sec %lf usec\n", (int64_t) diff->tv_sec, diff->tv_nsec * 0.001);

                    // Set avg
                    if (fresh_run)
                    {
                        avg_sec = diff->tv_sec;
                        avg_nsec = diff->tv_nsec;
                        fresh_run = false;
                        N++;
                    }
                    else
                    {
                        avg_sec = (avg_sec + (diff->tv_sec / (float)N)) / (1 + (1 / (float)N));
                        avg_nsec = (avg_nsec + (diff->tv_nsec / (float)N)) / (1 + (1 / (float)N));

                        N++;
                    }

                    printf("Avg:  %lf sec %lf usec\n", avg_sec, avg_nsec * 0.001);
                }
            }
            if (!server->GetClient(i)->connection_ready && !fresh_run)
            {
                // Log the data
                FILE *fp = fopen("data.txt", "a");
                fprintf(fp, "packet size, avg sec, avg usec: %d %lf %lf\n\n", NETFRAME_MAX_PAYLOAD_SIZE, avg_sec, avg_nsec * 0.001);
                fclose(fp);

                // Just quit
                exit(42);
            }
            delete frame;
        }
        usleep(5000);
    }
    delete server;
    delete[] buf;
    return 0;
}