/**
 * @file network_client.cpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Network Client Implementation
 * @version 1.0
 * @date 2021-09-10
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "network_common.hpp"
#include "network_private.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <new>

#ifndef NETWORK_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <time.h>
#include <assert.h>
#include "meb_print.h"
#ifdef __linux__
#include <signal.h>
#endif
#include "network_client.hpp"

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int ssl_lib_init = 0;

int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s)
#ifndef NETWORK_WINDOWS
{
    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    // Set non-blocking.
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg |= O_NONBLOCK;
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_SETFL)");
        erprintlf(errno);
        return -1;
    }

    // Trying to connect with timeout.
    res = connect(socket, address, socket_size);
    if (res < 0)
    {
        if (errno == EINPROGRESS)
        {
            dbprintlf(YELLOW_FG "EINPROGRESS in connect() - selecting");
            do
            {
                if (tout_s > 1)
                {
                    tv.tv_sec = tout_s;
                }
                else
                {
                    tv.tv_sec = 1; // Minimum 1 second.
                }
                tv.tv_usec = 0;
                FD_ZERO(&myset);
                FD_SET(socket, &myset);
                res = select(socket + 1, NULL, &myset, NULL, &tv);
                if (res < 0 && errno != EINTR)
                {
                    dbprintlf(RED_FG "Error connecting.");
                    erprintlf(errno);
                    return -1;
                }
                else if (res > 0)
                {
                    // Socket selected for write.
                    lon = sizeof(int);
                    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
                    {
                        dbprintlf(RED_FG "Error in getsockopt()");
                        erprintlf(errno);
                        return -1;
                    }

                    // Check the value returned...
                    if (valopt)
                    {
                        dbprintlf(RED_FG "Error in delayed connection()");
                        erprintlf(valopt);
                        return -1;
                    }
                    break;
                }
                else
                {
                    dbprintlf(RED_FG "Timeout in select(), cancelling!");
                    return -1;
                }
            } while (1);
        }
        else
        {
            fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
            dbprintlf(RED_FG "Error connecting.");
            erprintlf(errno);
            return -1;
        }
    }
    // Set to blocking mode again...
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg &= (~O_NONBLOCK);
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    return socket;
}
#else
{
    int res = connect(socket, address, socket_size);
    if (res)
        return -1;
    return 1;
}
#endif

void InitializeSSLLibrary()
{
    if (ssl_lib_init++ == 0)
    {
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
#ifdef __linux__
        signal(SIGPIPE, SIG_IGN);
#endif
#ifdef NETWORK_WINDOWS
        WSADATA wsaData;
        int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (ret != 0)
        {
            dbprintlf(FATAL "WSAStartup failed with error: %d", ret);
        }
#endif
    }
}

SSL_CTX *InitializeSSLClient(void)
{
    InitializeSSLLibrary();
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL)
    {
        dbprintlf(FATAL "Could create SSL context");
    }
    else
    {
        SSL_CTX_set_dh_auto(ctx, 1);
    }
    return ctx;
}

void DestroySSL()
{
    if (--ssl_lib_init == 0)
    {
        ERR_free_strings();
        EVP_cleanup();
#ifdef NETWORK_WINDOWS
        WSACleanup();
#endif
    }
}

int NetDataClient::OpenSSLConn()
{
    if (ctx != NULL && csocket_ready)
    {
        cssl = SSL_new(ctx);
        if (!SSL_set_fd(cssl, _socket))
        {
            dbprintlf("Could not open SSL connection");
            return -1;
        }
        int ssl_err = SSL_connect(cssl);
        if (ssl_err <= 0)
        {
            dbprintlf("SSL error %d, %d", ssl_err, SSL_get_error(cssl, ssl_err));
            CloseSSLConn();
            return -1;
        }
        ssl_ready = true;
        return 1;
    }
    return -1;
}

NetDataClient::~NetDataClient()
{
    connection_ready = false;
    Close();
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    ctx = NULL;
    DestroySSL();
    if (auth_token != nullptr)
        delete auth_token;
    auth_token = nullptr;
    if (certinfo != nullptr)
        delete certinfo;
    certinfo = nullptr;
}

NetDataClient::NetDataClient(const char *ip_addr, NetPort server_port, sha1_hash_t *auth, int polling_rate, ClientClass dclass, ClientID did)
    : NetData()
{
    ctx = InitializeSSLClient();
    if (ip_addr == NULL)
        strcpy(this->ip_addr, "127.0.0.1");
    else
    {
        strncpy(this->ip_addr, ip_addr, sizeof(this->ip_addr));
    }
    if (auth == NULL || auth == nullptr)
    {
        dbprintlf(FATAL "Authentication token not provided, exiting");
        throw std::invalid_argument("Auth is NULL");
    }
    if (auth->validate() == false)
    {
        dbprintlf(FATAL "Authentication hash invalid!");
        throw std::invalid_argument("Auth is uninitialized");
    }
    if (auth_token == nullptr)
        auth_token = new sha1_hash_t();
    auth_token->copy(*auth);
    this->polling_rate = polling_rate;
    strcpy(disconnect_reason, "N/A");
    memset(server_ip, 0x0, sizeof(struct sockaddr_in));
    server_ip->sin_family = AF_INET;
    server_ip->sin_port = htons((int)server_port);
    devclass = dclass;
    devId = did;
    origin = ((uint32_t)dclass << 8) | ((uint32_t)did);
};

int NetDataClient::ConnectToServer()
{
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s.", ip_addr);

    // This is already done when initializing network_data.
    // network_data->serv_ip->sin_port = htons(server_port);
    _socket = socket(AF_INET, SOCK_STREAM, 0);
    if (_socket < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, ip_addr, &server_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(_socket, (struct sockaddr *)server_ip, sizeof(server_ip), 1) < 0)
    {
        dbprintlf(FATAL "Connection failure.");
        connect_status = -3;
    }
    else
    {
        connect_status = 1;
        csocket_ready = true;
        dbprintlf(GREEN_FG "Set connection ready");
    }
    if (connect_status < 0)
    {
        Close();
        return -200;
    }
    // If the socket is closed, but recv(...) was already called, it will be stuck trying to receive forever from a socket that is no longer active. One way to fix this is to close the RX thread and restart it. Alternatively, we could implement a recv(...) timeout, ensuring a fresh socket value is used.
    // Here, we implement a recv(...) timeout.
    struct timeval timeout;
    timeout.tv_sec = RECV_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout); // connection timeout set
#if !defined(__linux__)
#if !defined(NETWORK_WINDOWS)
    int set = 1;
    setsockopt(_socket, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
#endif
    int retval;
    NetVertex server_v = 0;
    NetFrame *frame;
    // Step 1. Receive server ping
    // frame = new NetFrame();
    // for (int i = 0; (i < 20) && (frame->recvFrame(this) < 0); i++)
    //     ;
    // if (frame->getType() != NetType::POLL)
    // {
    //     dbprintlf("Did not receive a poll packet, received %d", frame->getType());
    //     Close();
    //     delete frame;
    //     return -2;
    // }
    // server_v = frame->getOrigin();
    // dbprintlf("Server Origin: 0x%x", server_v);
    // delete frame;
    // Step 2. Connect SSL
    if ((retval = OpenSSLConn()) > 0)
    {
        dbprintlf("Connected to %s over SSL", ip_addr);
    }
    else
    {
        dbprintlf("SSL connect failed: %d", retval);
        Close();
        return -3;
    }
    // Step 3. Send Auth Token
    frame = new NetFrame((uint8_t *)auth_token->getBytes(), SHA512_DIGEST_LENGTH, SRV_AUTH_TOKEN, NetType::SRV, FrameStatus::ACK, server_v);
    usleep(20000);
    if (frame->sendFrame(this) <= 0)
    {
        delete frame;
        dbprintlf("Could not send auth token, exiting");
        Close();
        return -4;
    }
    delete frame;
    // Step 4. Retrieve assigned vertex
    frame = new NetFrame();
    for (int i = 0; (i < 20) && (frame->recvFrame(this, i == 19) < 0); i++)
    {
        usleep(20000);
    }
    if (frame->getType() != NetType::SRV)
    {
        dbprintlf("Expecting %d, got %d for frame type", (int)NetType::SRV, (int)frame->getType());
        Close();
        delete frame;
        return -5;
    }
    else if (frame->getPayloadSize() != 2 * sizeof(NetVertex))
    {
        dbprintlf("Expecting package size %lu, got %d (2x NetVertex)", 2 * sizeof(NetVertex), frame->getPayloadSize());
        Close();
        delete frame;
        return -6;
    }
    NetVertex vertices[2];
    frame->retrievePayload(vertices, sizeof(vertices));
    origin = vertices[0];
    server_vertex = vertices[1];
    delete frame;
    // Step 5. Send ACK
    frame = new NetFrame(&origin, sizeof(NetVertex), 0, NetType::SRV, FrameStatus::ACK, server_vertex);
    if (frame->sendFrame(this) <= 0)
    {
        dbprintlf("Failed to send ACK to server, server closed connection");
        delete frame;
        Close();
        return -7;
    }
    connection_ready = true;
    GetCerts();

    return connect_status;
}

#ifndef NETWORK_WINDOWS
void *gs_polling_thread(void *args)
#else
DWORD WINAPI gs_polling_thread(LPVOID args)
#endif
{
    dbprintlf(BLUE_FG "Beginning polling thread.");
    NetDataClient *network_data = (NetDataClient *)args;
#ifndef NETWORK_WINDOWS
    sleep(1);
#else
    Sleep(1000);
#endif
    network_data->recv_active = true;
    while (network_data->recv_active)
    {
        if (network_data->connection_ready)
        {
            NetFrame *polling_frame = new NetFrame(NULL, 0, 0, NetType::POLL, FrameStatus::NONE, network_data->server_vertex);
            polling_frame->sendFrame(network_data);
            polling_frame->print();
            delete polling_frame;
        }
        else
        {
            dbprintlf("Connect to server from poll\n");
            network_data->ConnectToServer();
        }
        if (network_data->polling_rate < 1000)
            network_data->polling_rate = 1000; // minimum 1 ms
#ifndef NETWORK_WINDOWS
        usleep(network_data->polling_rate * 1000);
#else
        Sleep(network_data->polling_rate);
#endif
    }
    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
#ifndef NETWORK_WINDOWS
    return nullptr;
#else
    return 0;
#endif
}

std::string *extractStringFromX509Info(const char *info, const char *key)
{
    std::string *str = nullptr;
    char *begin = NULL, *end = NULL;
    int keybloblen = strlen(key) + strlen("/=");
    char *keyblob = new char[keybloblen + 1];
    sprintf(keyblob, "/%s=", key);
    if ((begin = (char *)strstr(info, keyblob)) != NULL)
    {
        end = strstr(begin + 1, "/"); // next key
        int len = end - begin - keybloblen;
        if (len > 0 && end != NULL)
        {
            str = new std::string(begin + keybloblen, len);
        }
        else
        {
            str = new std::string(begin + keybloblen);
        }
    }
    delete[] keyblob;
    return str;
}

/*
 * Cert verification resources:
 * 
 * https://stackoverflow.com/questions/16291809/programmatically-verify-certificate-chain-using-openssl-api
 * https://gist.github.com/sunipkm/79b0f7b4dd3d53ddbb724c8b0bbd8890
 * https://zakird.com/2013/10/13/certificate-parsing-with-openssl (mirror: https://gist.github.com/sunipkm/f53693abeeccb03599405a721c13d78c)
 * https://docs.scylladb.com/operating-scylla/security/generate-certificate/
 * 
 * https://superuser.com/questions/1675013/for-websites-is-your-passwords-hash-computed-on-the-client-or-the-server-side
 * 
 * For now, copy I had to copy the lets_encrypt_r3 root certificate to /etc/ssl/certs to get verification to pass with lets encrypt certs (cert, key, fullchain) generated for sunipkm.tk
 * 
 */

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    if (!ok)
    {
        /* check the error code and current cert*/
        // X509 *currentCert = X509_STORE_CTX_get_current_cert(ctx);
        int certError = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        printf("Error depth %d, certError %d", depth, certError);
    }

    return (ok);
}

const char* get_validation_errstr(long e) {
	switch ((int) e) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			return "ERR_UNABLE_TO_GET_ISSUER_CERT";
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			return "ERR_UNABLE_TO_GET_CRL";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			return "ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			return "ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			return "ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
			return "ERR_CERT_SIGNATURE_FAILURE";
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			return "ERR_CRL_SIGNATURE_FAILURE";
		case X509_V_ERR_CERT_NOT_YET_VALID:
			return "ERR_CERT_NOT_YET_VALID";
		case X509_V_ERR_CERT_HAS_EXPIRED:
			return "ERR_CERT_HAS_EXPIRED";
		case X509_V_ERR_CRL_NOT_YET_VALID:
			return "ERR_CRL_NOT_YET_VALID";
		case X509_V_ERR_CRL_HAS_EXPIRED:
			return "ERR_CRL_HAS_EXPIRED";
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			return "ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			return "ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
			return "ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			return "ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
		case X509_V_ERR_OUT_OF_MEM:
			return "ERR_OUT_OF_MEM";
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			return "ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			return "ERR_SELF_SIGNED_CERT_IN_CHAIN";
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			return "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			return "ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			return "ERR_CERT_CHAIN_TOO_LONG";
		case X509_V_ERR_CERT_REVOKED:
			return "ERR_CERT_REVOKED";
		case X509_V_ERR_INVALID_CA:
			return "ERR_INVALID_CA";
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			return "ERR_PATH_LENGTH_EXCEEDED";
		case X509_V_ERR_INVALID_PURPOSE:
			return "ERR_INVALID_PURPOSE";
		case X509_V_ERR_CERT_UNTRUSTED:
			return "ERR_CERT_UNTRUSTED";
		case X509_V_ERR_CERT_REJECTED:
			return "ERR_CERT_REJECTED";
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			return "ERR_SUBJECT_ISSUER_MISMATCH";
		case X509_V_ERR_AKID_SKID_MISMATCH:
			return "ERR_AKID_SKID_MISMATCH";
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			return "ERR_AKID_ISSUER_SERIAL_MISMATCH";
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			return "ERR_KEYUSAGE_NO_CERTSIGN";
		case X509_V_ERR_INVALID_EXTENSION:
			return "ERR_INVALID_EXTENSION";
		case X509_V_ERR_INVALID_POLICY_EXTENSION:
			return "ERR_INVALID_POLICY_EXTENSION";
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			return "ERR_NO_EXPLICIT_POLICY";
		case X509_V_ERR_APPLICATION_VERIFICATION:
			return "ERR_APPLICATION_VERIFICATION";
		default:
			return "ERR_UNKNOWN";
	}
}

void NetDataClient::GetCerts()
{
    if (cssl == NULL || !ssl_ready)
        return;
    X509 *cert = NULL;
    char *line = NULL;
    cert = SSL_get_peer_certificate(cssl); /* get the server's certificate */
    STACK_OF(X509) *sk = SSL_get_peer_cert_chain(cssl);
    if (sk == NULL)
    {
        sk = sk_X509_new_null();
    }
    sk_X509_push(sk, cert);
    if (cert != NULL)
    {
        char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        dbprintlf(GREEN_FG "Cert subject: %s", subj);
        dbprintlf(GREEN_FG "Cert issuer: %s", issuer);
        OPENSSL_free(subj);
        OPENSSL_free(issuer);
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        dbprintlf(YELLOW_FG "Cert line: %s", line);
        certinfo = new certinfo_t;
        certinfo->country = extractStringFromX509Info(line, "C");
        certinfo->state = extractStringFromX509Info(line, "ST");
        certinfo->loc = extractStringFromX509Info(line, "L");
        certinfo->org = extractStringFromX509Info(line, "O");
        certinfo->org_unit = extractStringFromX509Info(line, "OU");
        certinfo->issuer = extractStringFromX509Info(line, "CN");
        certinfo->issuer_email = extractStringFromX509Info(line, "/emailAddress");
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        free(line);      /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    }
    else
    {
        dbprintlf(FATAL "Info: No client certificates configured.");
    }
    X509_STORE *x509_store = NULL;
    X509_STORE_CTX *x509_store_ctx = NULL;
    x509_store = X509_STORE_new();
    int rc = X509_STORE_load_locations(x509_store, NULL, "/etc/ssl/certs"); // TODO: certificate load location selection? Build time default?
    if (rc != 1)
    {
        dbprintlf("Could not store %d", rc);
    }
    int num = sk_X509_num(sk);
    // X509 *top = sk_X509_value(sk, num-1);
    // X509_STORE_add_cert(x509_store, top); // adds self signed certs to store, allowing verification to return true
    X509_STORE_set_verify_cb(x509_store, verify_cb);
    X509_STORE_set_flags(x509_store, 0);
    x509_store_ctx = X509_STORE_CTX_new();

    X509_STORE_CTX_init(x509_store_ctx, x509_store, cert, sk);

    X509_STORE_CTX_set_purpose(x509_store_ctx, X509_PURPOSE_ANY);
    int ret = X509_verify_cert(x509_store_ctx);
    dbprintlf(RED_FG "Verify Cert: %d", ret);
    if (ret != 1)
    {
        int err = X509_STORE_CTX_get_error(x509_store_ctx);
        dbprintlf(RED_FG "Verify cert err: " YELLOW_FG "%s", get_validation_errstr(err));
    }
    if (x509_store_ctx != NULL)
        X509_STORE_CTX_free(x509_store_ctx);
    if (x509_store != NULL)
        X509_STORE_free(x509_store);
}

void NetDataClient::PrintCerts()
{
    if (certinfo != nullptr)
    {
        if (certinfo->country != nullptr)
            dbprintlf(GREEN_FG "Country: %s", certinfo->country->c_str());
        if (certinfo->state != nullptr)
            dbprintlf(GREEN_FG "State: %s", certinfo->state->c_str());
        if (certinfo->loc != nullptr)
            dbprintlf(GREEN_FG "Location: %s", certinfo->loc->c_str());
        if (certinfo->org != nullptr && certinfo->org_unit != nullptr)
            dbprintlf(GREEN_FG "Organization: %s, Unit: %s", certinfo->org->c_str(), certinfo->org_unit->c_str());
        if (certinfo->issuer != nullptr && certinfo->issuer_email != nullptr)
            dbprintlf(GREEN_FG "Issuer: %s (%s)", certinfo->issuer->c_str(), certinfo->issuer_email->c_str());
    }
}