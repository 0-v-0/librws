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


#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <string.h>

#if defined(CMAKE_BUILD)
#undef CMAKE_BUILD
#endif


#if defined(XCODE)
#include "librws.h"
#else
#include <librws.h>
#endif


#if defined(CMAKE_BUILD)
#undef CMAKE_BUILD
#endif

static rws_socket _socket = NULL;

static void on_socket_received_text(rws_socket socket, const char * text, const unsigned int length, rws_bool is_finished) {
    char buff[8*1024];
    memcpy(buff, text, length);
    buff[length] = '\0';
    printf("\nSocket text: %s\n", buff);
}

static void on_socket_received_bin(rws_socket socket, const void * data, const unsigned int length, rws_bool is_finished) {
    char buff[8*1024];
    memcpy(buff, data, length);
    buff[length] = 0;
    printf("\nSocket bin: <%s>\n", buff);
}

static void on_socket_recvd_pong(rws_socket socket){
    printf("\nSocket pong\n");
}

static void on_socket_connected(rws_socket socket) {
    printf("\nSocket connected\n");
}

static void on_socket_disconnected(rws_socket socket) {
    rws_error error = rws_socket_get_error(socket);
    if (error) {
        printf("\nSocket disconnect with code, error: %i, %s\n",
              rws_error_get_code(error),
              rws_error_get_description(error));
    } else {
        printf("\nSocket disconnect\n");
    }
}

int main(int argc, char* argv[]) {
    const char * test_send_text =
        "{\"version\":\"1.0\",\"supportedConnectionTypes\":[\"websocket\"],\"minimumVersion\":\"1.0\",\"channel\":\"/meta/handshake\"}";
    _socket = rws_socket_create(); // create and store socket handle
    assert(_socket);

    rws_socket_set_scheme(_socket, "ws");
    rws_socket_set_host(_socket, "echo.websocket.org");
    rws_socket_set_path(_socket, "/");
    rws_socket_set_port(_socket, 80);

    rws_socket_set_on_disconnected(_socket, &on_socket_disconnected);
    rws_socket_set_on_connected(_socket, &on_socket_connected);
    rws_socket_set_on_received_text(_socket, &on_socket_received_text);
    rws_socket_set_on_received_bin(_socket, &on_socket_received_bin);
    rws_socket_set_on_received_pong(_socket, &on_socket_recvd_pong);

//#if !defined(RWS_APPVEYOR_CI)
    // connection denied for client applications
    rws_socket_connect(_socket);
    usleep(1000*1000);
//#endif

    rws_socket_send_ping(_socket);
    usleep(1000*1000);

    rws_socket_send_text(_socket, test_send_text);
    usleep(1000*1000);

    rws_socket_disconnect_and_release(_socket);
    return 0;
}

