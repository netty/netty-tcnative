/*
 * Copyright 2023 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include "tcn_lock_rw.h"
#include <shared_mutex>
#include <mutex>

tcn_lock_rw_t tcn_lock_rw_create() {
    // Once we switch to c++17 we should use std::shared_mutex
    return (tcn_lock_rw_t) new std::shared_timed_mutex;
}

void tcn_lock_rw_destroy(tcn_lock_rw_t lock) {
    delete (std::shared_timed_mutex *) lock;
}

tcn_lock_w_t tcn_lock_w_acquire(tcn_lock_rw_t lock) {
    return (tcn_lock_w_t) new std::unique_lock<std::shared_timed_mutex>(*((std::shared_timed_mutex *) lock));
}

void tcn_lock_w_release(tcn_lock_w_t lock) {
    delete (std::unique_lock<std::shared_timed_mutex> *) lock;
}

tcn_lock_r_t tcn_lock_r_acquire(tcn_lock_rw_t lock) {
    return (tcn_lock_r_t) new std::unique_lock<std::shared_timed_mutex>(*((std::shared_timed_mutex *) lock));
}

void tcn_lock_r_release(tcn_lock_r_t lock) {
    delete (std::unique_lock<std::shared_timed_mutex> *) lock;
}
