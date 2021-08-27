#include "network_common.hpp"
#include <openssl/err.h>
#include <new>
#include <unistd.h>

int ssl_lib_init = 0;

void InitializeSSLLibrary()
{
    if (ssl_lib_init++ == 0)
    {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
    }
}

void DestroySSLLibrary()
{
    if (--ssl_lib_init == 0)
    {
        ERR_free_strings();
        EVP_cleanup();
    }
}

void NetData::close_ssl_conn()
{
    if (cssl != NULL)
    {
        ssl_ready = false;
        SSL_shutdown(cssl);
        SSL_free(cssl);
        cssl = NULL;
    }
    if (ctx != NULL)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    DestroySSLLibrary();
}

void NetData::Close()
{
    // Cancel the polling thread
    if (polling_thread)
        pthread_cancel(polling_thread);
    polling_thread = 0;
    // Close SSL connection
    if (ssl_ready)
        close_ssl_conn();
    connection_ready = false;
    // Close C socket connection
    close(_socket);
    _socket = -1;
}