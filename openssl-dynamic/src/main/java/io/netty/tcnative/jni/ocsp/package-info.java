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

/**
 * To test for the presence or absence OCSP staples use OpenSSL's client and look
 * for the OCSP staple response in the output. Wireshark and browsers that support
 * OCSP stapling such as Firefox can be also very useful for testing.
 * 
 * <code>
 * $ openssl s_client -tlsextdebug -status -connect www.squarespace.com:443
 * </code>
 * 
 * It'll either say that "OCSP response: no response sent" or something like this:
 * 
 * <code>
 * OCSP response: 
 * ======================================
 * OCSP Response Data:
 *     OCSP Response Status: successful (0x0)
 *     Response Type: Basic OCSP Response
 *     Version: 1 (0x0)
 *     Responder Id: 5168FF90AF0207753CCCD9656462A212B859723B
 *     Produced At: Nov  5 09:57:00 2016 GMT
 *     Responses:
 *     Certificate ID:
 *       Hash Algorithm: sha1
 *       Issuer Name Hash: CF26F518FAC97E8F8CB342E01C2F6A109E8E5F0A
 *       Issuer Key Hash: 5168FF90AF0207753CCCD9656462A212B859723B
 *       Serial Number: 0414BC6590618A8E19F019CC9473088F
 *     Cert Status: good
 *     This Update: Nov  5 09:57:00 2016 GMT
 *     Next Update: Nov 12 09:12:00 2016 GMT
 * 
 *     Signature Algorithm: sha256WithRSAEncryption
 *          ac:58:c0:b7:22:30:bc:43:36:76:2d:fd:c1:bf:2b:b3:65:49:
 *          22:47:4c:c7:46:6d:75:f8:fc:ed:1b:0c:5a:57:08:0d:bc:15:
 *          b4:b1:25:5f:91:1d:05:ac:2e:b8:60:37:5c:53:7e:c6:5b:09:
 *          4f:23:9b:ed:3d:db:d1:7e:57:a3:01:ce:ab:7e:2a:f0:36:cd:
 *          13:52:e4:b0:24:41:d1:85:f8:f2:6b:86:0d:9c:e9:68:c7:9d:
 *          64:9e:6d:35:19:d6:89:ae:a8:b1:8d:35:d4:71:fd:f0:8a:c7:
 *          ad:9e:e7:c3:db:22:e5:92:e0:1f:dc:14:51:44:77:07:63:a6:
 *          e2:aa:4e:f0:c9:3f:7e:a6:13:c7:c6:56:f9:ec:d3:2b:61:75:
 *          b7:54:c2:26:24:d2:33:d0:ba:df:d2:8e:1d:76:09:a7:07:97:
 *          0c:1e:86:96:14:04:10:28:c8:35:75:66:e2:1e:45:a6:53:e7:
 *          dd:79:ed:4c:be:97:7c:57:a9:24:ec:55:7f:4b:94:75:3c:7a:
 *          d3:af:9f:36:bf:3d:c7:c6:03:d9:a2:b2:c7:4e:a0:a9:a2:d7:
 *          dd:34:fa:ea:4e:6d:68:7c:c0:4d:43:d1:ac:de:b7:71:35:73:
 *          78:1a:e7:3d:a2:f3:c0:2c:cb:d0:1d:a9:ae:bb:e4:c7:c0:f2:
 *          89:98:de:fa
 * ======================================
 * </code>
 */
package io.netty.tcnative.jni.ocsp;