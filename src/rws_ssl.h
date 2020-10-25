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

#ifndef __RWS_SSL_H__
#define __RWS_SSL_H__ 1

#include "rws_common.h"

#include <stdio.h>
#include <stdbool.h>

#ifdef RWS_SSL_ENABLE

typedef struct _rws_ssl_struct _rws_ssl;

int rws_ssl_connect(rws_socket s);

int rws_ssl_send(rws_socket s, const unsigned char *buf, size_t len);

int rws_ssl_recv(rws_socket s, unsigned char *buf, size_t len);

void rws_ssl_close(rws_socket s);

bool rws_ssl_err_want_read(int error_code);

bool rws_ssl_err_non_fatal(int error_code);

#endif // RWS_SSL_ENABLE

#endif // __RWS_SSL_H__

