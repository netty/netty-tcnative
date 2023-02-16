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
#include "tcn_atomic.h"
#include <atomic>

tcn_atomic_uint32_t tcn_atomic_uint32_create() {
    return (tcn_atomic_uint32_t) new std::atomic<uint32_t>(0);
}

void tcn_atomic_uint32_destroy(tcn_atomic_uint32_t atomic) {
    delete (std::atomic<uint32_t> *) atomic;
}

uint32_t tcn_atomic_uint32_get(tcn_atomic_uint32_t atomic) {
    return *((std::atomic<uint32_t> *) atomic);
}

void tcn_atomic_uint32_increment(tcn_atomic_uint32_t atomic) {
    auto *p = (std::atomic<uint32_t> *) atomic;
    ++(*p);
}
