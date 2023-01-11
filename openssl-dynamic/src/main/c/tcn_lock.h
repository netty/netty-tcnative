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
#ifndef TCN_LOCK_H
#define TCN_LOCK_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef void* tcn_lock_t;

tcn_lock_t tcn_lock_new();

void tcn_lock_free(tcn_lock_t* lock);

void tcn_lock_acquire(tcn_lock_t lock);

void tcn_lock_release(tcn_lock_t lock);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif //TCN_LOCK_H
