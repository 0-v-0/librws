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

#ifndef __RWS_THREAD_H__
#define __RWS_THREAD_H__ 1

#include <stdio.h>

typedef rws_handle _rws_mutex;

typedef rws_handle _rws_cond;

typedef struct rws_thread_struct * _rws_thread;

typedef void (*_rws_thread_funct)(void * user_object);

/**
 @brief Create thread object that start immidiatelly.
 */
_rws_thread rws_thread_create(_rws_thread_funct thread_function, void * user_object);

/**
 @brief Creates recursive mutex object.
 */
_rws_mutex rws_mutex_create_recursive(void);

/**
 @brief Lock mutex object.
 */
void rws_mutex_lock(_rws_mutex mutex);

/**
 @brief Unlock mutex object.
 */
void rws_mutex_unlock(_rws_mutex mutex);

/**
 @brief Release mutex object.
 */
void rws_mutex_delete(_rws_mutex mutex);

#if !defined(RWS_OS_WINDOWS)

/**
 @brief Creates condition object.
 */
_rws_cond rws_cond_create(void);

/**
 @brief Signal a condition
 */
void rws_cond_signal(_rws_cond cond);

/**
 @brief Wait a condition
 */
void rws_cond_wait(_rws_cond cond, _rws_mutex mutex);

/**
 @brief Release a condition
 */
void rws_cond_delete(_rws_cond cond);

#endif

/**
 @brief Pause current thread for a number of milliseconds.
 */
void rws_thread_sleep(const unsigned int millisec);

#endif

