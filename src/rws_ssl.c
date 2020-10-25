/*
 *   Copyright (c) 2014 - 2019 Oleh Kulykov <info@resident.name>
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

/*
 * Copyright (C) 2015-2019 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include "../librws.h"
#include "rws_socket.h"
#include "rws_memory.h"
#include "rws_string.h"
#include "rws_ssl.h"

#ifdef RWS_SSL_ENABLE

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL 1
#endif

#define RWS_READ_TIMEOUT        5000
#define RWS_WRITE_TIMEOUT       5000

struct _rws_ssl_struct {
    mbedtls_ssl_context ssl_ctx;        /* mbedtls ssl context */
    mbedtls_net_context net_ctx;        /* Fill in socket id */
    mbedtls_ssl_config ssl_conf;        /* SSL configuration */
    //mbedtls_entropy_context entropy;
    //mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt_profile profile;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
};

void rws_tls_net_init(void *ctx)
{
    ((mbedtls_net_context *)ctx)->fd = -1;
}

void rws_tls_net_free(void *ctx)
{
    int fd = ((mbedtls_net_context *)ctx)->fd;
    if (fd < 0) return;
    shutdown(fd, 2);
    close(fd);
    ((mbedtls_net_context *)ctx)->fd = -1;
}

int rws_tls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
    int ret;
    int fd = ((mbedtls_net_context *)ctx)->fd;
    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    struct timeval interval = {RWS_WRITE_TIMEOUT / 1000, (RWS_WRITE_TIMEOUT % 1000) * 1000};
    if (interval.tv_sec < 0 || (interval.tv_sec == 0 && interval.tv_usec <= 100)) {
        interval.tv_sec = 0;
        interval.tv_usec = 10000;
    }
    /*set send timeout to avoid send block*/
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&interval, sizeof(struct timeval))) {
        return -1;
    }

    ret = (int)send(fd, buf, len, 0);
    if (ret < 0) {
        if (errno == EPIPE || errno == ECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;

        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_WRITE;

        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}

int rws_tls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    ret = (int) recv(fd, buf, len, 0);
    if (ret < 0) {
        // if (errno == EAGAIN)
        //     return MBEDTLS_ERR_SSL_WANT_READ;

        if (errno == EPIPE || errno == ECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;

        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_READ;

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;
}

int rws_tls_net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    int ret;
    struct timeval tv;
    fd_set read_fds;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    /* no wait if timeout == 0 */
    ret = select(fd + 1, &read_fds, NULL, NULL, &tv);

    /* Zero fds ready means we timed out */
    if (ret == 0)
        return MBEDTLS_ERR_SSL_TIMEOUT;

    if (ret < 0)
    {
        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_READ;

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    /* This call will not block */
    return rws_tls_net_recv(ctx, buf, len);
}

static int _rws_random(void *p_rng, unsigned char *output, size_t output_len)
{
    int i;
    uint32_t random;
    int mod = output_len % 4;
    int count = 0;
    static uint32_t rnd = 0x12345;
    for (i = 0; i < output_len / 4; i++) {
        random = rnd * 0xFFFF777;
        rnd = random;
        output[count++] = (random >> 24) & 0xFF;
        output[count++] = (random >> 16) & 0xFF;
        output[count++] = (random >> 8) & 0xFF;
        output[count++] = (random) & 0xFF;
    }
    random = rnd * 0xFFFF777;
    rnd = random;
    for (i = 0; i < mod; i++) {
        output[i + count] = (random >> 8 * i) & 0xFF;
    }
    return 0;
}

static void _rws_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    RWS_DBG("%s\n", str);
}

int rws_ssl_connect(rws_socket s)
{
    int authmode = MBEDTLS_SSL_VERIFY_NONE;
    // const char *pers = "https";
    int ret = 0;
    uint32_t flags;
    // char port[10] = {0};
    _rws_ssl *ssl;

    s->ssl = rws_malloc_zero(sizeof(_rws_ssl));
    if (!s->ssl) {
        ret = -1;
        goto exit;
    }

    ssl = s->ssl;

    if (s->server_cert)
        authmode = MBEDTLS_SSL_VERIFY_REQUIRED;

    /*
     * Initialize the RNG and the session data
     */
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif
    rws_tls_net_init(&ssl->net_ctx);
    //mbedtls_net_init(&ssl->net_ctx);
    mbedtls_ssl_init(&ssl->ssl_ctx);
    mbedtls_ssl_config_init(&ssl->ssl_conf);
    mbedtls_x509_crt_init(&ssl->cacert);
    mbedtls_x509_crt_init(&ssl->clicert);
    mbedtls_pk_init(&ssl->pkey);
    /*
    mbedtls_ctr_drbg_init(&ssl->ctr_drbg);
    mbedtls_entropy_init(&ssl->entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ssl->ctr_drbg,
                                       mbedtls_entropy_func,
                                       &ssl->entropy,
                                       (const unsigned char*)pers,
                                       strlen(pers))) != 0) {
        RWS_DBG("mbedtls_ctr_drbg_seed() failed, returned %d\n", ret);
        ret = -1;
        goto exit;
    }
    */

    /*
    * Load the Client certificate
    */
    if (s->client_cert && s->client_pk) {
        ret = mbedtls_x509_crt_parse(&ssl->clicert, (const unsigned char *)s->client_cert, s->client_cert_len);
        if (ret < 0) {
            RWS_ERR("failed! mbedtls_x509_crt_parse() returned %d\n", ret);
            ret = -1;
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&ssl->pkey, (const unsigned char *)s->client_pk, s->client_pk_len, NULL, 0);
        if (ret != 0) {
            RWS_ERR("failed! mbedtls_pk_parse_key() returned %d\n", ret);
            ret = -1;
            goto exit;
        }
    }

    /*
    * Load the trusted CA
    */
    /* cert_len passed in is gotten from sizeof not strlen */
    if (s->server_cert &&
        ((ret = mbedtls_x509_crt_parse(&ssl->cacert,
                                         (const unsigned char *)s->server_cert,
                                         s->server_cert_len)) < 0)) {
        RWS_ERR("failed! mbedtls_x509_crt_parse() returned %d\n", ret);
        ret = -1;
        goto exit;
    }

    /*
     * Start the connection
     */
    /*
    snprintf(port, sizeof(port), "%d", client->port) ;
    if ((ret = mbedtls_net_connect(&ssl->net_ctx, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        RWS_ERR("failed! mbedtls_net_connect() returned %d\n", ret);
        goto exit;
    }
    */
    RWS_DBG("%s-%d: start to connec to host\n", __func__, __LINE__);
    rws_socket_connect_to_host(s);
    if (s->socket == RWS_INVALID_SOCKET){
        ret = -1;
        RWS_ERR("%s-%d: failed to connec to host\n", __func__, __LINE__);
        goto exit;
    } else {
        RWS_DBG("%s-%d: succeed to connec to host\n", __func__, __LINE__);
        ssl->net_ctx.fd = s->socket;
    }

    /*
     * Setup stuff
     */
    if ((ret = mbedtls_ssl_config_defaults(&ssl->ssl_conf,
                                             MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        RWS_ERR("failed! mbedtls_ssl_config_defaults() returned %d\n", ret);
        ret = -1;
        goto exit;
    }

    // TODO: add customerization encryption algorithm
    memcpy(&ssl->profile, ssl->ssl_conf.cert_profile, sizeof(mbedtls_x509_crt_profile));
    ssl->profile.allowed_mds = ssl->profile.allowed_mds | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_MD5);
    mbedtls_ssl_conf_cert_profile(&ssl->ssl_conf, &ssl->profile);

    mbedtls_ssl_conf_authmode(&ssl->ssl_conf, authmode);
    mbedtls_ssl_conf_ca_chain(&ssl->ssl_conf, &ssl->cacert, NULL);

    if (s->client_cert &&
        (ret = mbedtls_ssl_conf_own_cert(&ssl->ssl_conf, &ssl->clicert, &ssl->pkey)) != 0) {
        RWS_ERR("failed! mbedtls_ssl_conf_own_cert() returned %d\n", ret);
        ret = -1;
        goto exit;
    }

    mbedtls_ssl_conf_rng(&ssl->ssl_conf, _rws_random, NULL);
    mbedtls_ssl_conf_dbg(&ssl->ssl_conf, _rws_debug, NULL);

    if ((ret = mbedtls_ssl_setup(&ssl->ssl_ctx, &ssl->ssl_conf)) != 0) {
        RWS_ERR("failed! mbedtls_ssl_setup() returned %d\n", ret);
        ret = -1;
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl->ssl_ctx, &ssl->net_ctx, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    mbedtls_ssl_conf_read_timeout(&ssl->ssl_conf, 10000);

    /*
    * Handshake
    */
    RWS_DBG("%s-%d: start to handshake\n", __func__, __LINE__);
    while ((ret = mbedtls_ssl_handshake(&ssl->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            RWS_ERR("%s-%d: failed to handshake, returned %d\n", __func__, __LINE__, ret);
            ret = -1;
            goto exit;
        }
    }
    RWS_DBG("%s-%d: succeed to handshake\n", __func__, __LINE__);
    mbedtls_ssl_conf_read_timeout(&ssl->ssl_conf, 100);

    /*
     * Verify the server certificate
     * In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl->ssl_ctx)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        RWS_ERR("%s\n", vrfy_buf);
#endif
        RWS_ERR("%s-%d: failed to verify cert, authmode: %d\n", __func__, __LINE__, authmode);
        ret = -1;
    } else {
        RWS_DBG("%s-%d: succeed to verify cert, authmode: %d\n", __func__, __LINE__, authmode);
    }

exit:
    if (ret != 0) {
        s->error = rws_error_new_code_descr(rws_error_code_connect_to_host, "Failed connect to host");
        RWS_ERR("%s-%d: failed to connect ssl, code=[%d], error=[%s]\n",
               __func__, __LINE__, s->error->code, s->error->description);
        s->command = COMMAND_INFORM_DISCONNECTED;
        rws_ssl_close(s);
    }
    return ret;
}

int rws_ssl_send(rws_socket s, const unsigned char *buf, size_t len)
{
    _rws_ssl *ssl = s->ssl;
    if (!ssl) return -1;
    return mbedtls_ssl_write(&(s->ssl->ssl_ctx), buf, len);
}

int rws_ssl_recv(rws_socket s, unsigned char *buf, size_t len)
{
    _rws_ssl *ssl = s->ssl;
    if (!ssl) return -1;
    return mbedtls_ssl_read(&(s->ssl->ssl_ctx), buf, len);
}

void rws_ssl_close(rws_socket s)
{
    _rws_ssl *ssl = s->ssl;

    if (!ssl) return;

    s->ssl = NULL;
    s->client_cert = NULL;
    s->server_cert = NULL;
    s->client_pk = NULL;

    mbedtls_ssl_close_notify(&ssl->ssl_ctx);
    rws_tls_net_free(&ssl->net_ctx);
    //mbedtls_net_free(&ssl->net_ctx);
    mbedtls_x509_crt_free(&ssl->cacert);
    mbedtls_x509_crt_free(&ssl->clicert);
    mbedtls_pk_free(&ssl->pkey);
    mbedtls_ssl_free(&ssl->ssl_ctx);
    mbedtls_ssl_config_free(&ssl->ssl_conf);
    //mbedtls_ctr_drbg_free(&ssl->ctr_drbg);
    //mbedtls_entropy_free(&ssl->entropy);

    rws_free(ssl);
}

bool rws_ssl_err_want_read(int error_code)
{
    return MBEDTLS_ERR_SSL_WANT_READ == error_code;
}

bool rws_ssl_err_non_fatal(int error_code)
{
    switch (error_code) {
    case MBEDTLS_ERR_SSL_TIMEOUT:
    case MBEDTLS_ERR_SSL_CONN_EOF:
    case MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED:
    case MBEDTLS_ERR_SSL_NON_FATAL:
        return true;
    default:
        break;
    }
    return false;
}

#endif

