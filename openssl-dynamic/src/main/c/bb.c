/*
 * Copyright 2016 The Netty Project
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
/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tcn.h"
#include "bb.h"

TCN_IMPLEMENT_CALL(jlong, Buffer, address)(TCN_STDARGS, jobject bb)
{
    return P2J((*e)->GetDirectBufferAddress(e, bb));
}

TCN_IMPLEMENT_CALL(jlong, Buffer, size)(TCN_STDARGS, jobject bb)
{
    return (*e)->GetDirectBufferCapacity(e, bb);
}

// JNI Method Registration Table Begin
static const JNINativeMethod method_table[] = {
  { TCN_METHOD_TABLE_ENTRY(address, (Ljava/nio/ByteBuffer;)J, Buffer) },
  { TCN_METHOD_TABLE_ENTRY(size, (Ljava/nio/ByteBuffer;)J, Buffer) }
};

static const jint method_table_size = sizeof(method_table) / sizeof(method_table[0]);
// JNI Method Registration Table End

jint netty_internal_tcnative_Buffer_JNI_OnLoad(JNIEnv* env, const char* packagePrefix) {
    if (netty_internal_tcnative_util_register_natives(env, packagePrefix, "io/netty/internal/tcnative/Buffer", method_table, method_table_size) != 0) {
        return JNI_ERR;
    }
    return TCN_JNI_VERSION;
}

void netty_internal_tcnative_Buffer_JNI_OnUnLoad(JNIEnv* env) { }
