/*
   base64.cpp and base64.h

   base64 encoding and decoding with C++.

   Version: 1.01.00

   Copyright (C) 2004-2017 René Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/

/*
This is a modified version of the original file.
Based on the revision b70e17093131b8df9d0c1021e6cc48505693700d in
https://github.com/pluraf/cpp-base64

The modifications are licensed under the 3-Clause BSD License.
SPDX-License-Identifier: BSD-3-Clause

Copyright (c) 2024 Pluraf Embedded AB
Email: code@pluraf.com
*/


#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "base64.h"


const char * base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";


unsigned char is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '-') || (c == '_'));
}


int base64_encode(char * b64_dst, unsigned int out_len,
                  const unsigned char * bytes_to_encode, unsigned int in_len)
{
    int i = 0;
    int j = 0;
    unsigned int b64_len = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++) {
                if (b64_len >= out_len) {
                    return -1;
                }
                *b64_dst++ = base64_chars[char_array_4[i]];
                b64_len++;
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++) {
            if (b64_len >= out_len) {
                return -1;
            }
            *b64_dst++ = base64_chars[char_array_4[j]];
            b64_len++;
        }

        while((i++ < 3)) {
            if (b64_len >= out_len) {
                return -1;
            }
            *b64_dst++ = '=';
            b64_len++;
        }
    }

    *b64_dst = 0;
    return b64_len;
}


simple_array_t base64_decode(char * encoded_string, unsigned int in_len) {
    int i = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    simple_array_t decoded = {1024, malloc(1024), 0};
    unsigned char * ret = decoded.data;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i <4; i++) {
                char_array_4[i] = (strchr(base64_chars, char_array_4[i]) - base64_chars) & 0xff;
            }

            char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

            for (i = 0; (i < 3); i++) {
                *ret++ = char_array_3[i];
            }
            i = 0;
        }
    }

    if (i) {
        int j;
        for (j = 0; j < i; j++) {
            char_array_4[j] = (strchr(base64_chars, char_array_4[j]) - base64_chars) & 0xff;
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++) {
            *ret++ = char_array_3[j];
        }
    }

    *ret = 0;
    decoded.size = ret - decoded.data;
    return decoded;
}