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
#ifndef TCN_ATOMIC_H
#define TCN_ATOMIC_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif // __cplusplus

typedef void* tcn_atomic_uint32_t;

tcn_atomic_uint32_t tcn_atomic_uint32_create();

void tcn_atomic_uint32_destroy(tcn_atomic_uint32_t atomic);

uint32_t tcn_atomic_uint32_get(tcn_atomic_uint32_t atomic);

void tcn_atomic_uint32_increment(tcn_atomic_uint32_t atomic);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif //TCN_ATOMIC_H
