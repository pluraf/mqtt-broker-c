/* SPDX-License-Identifier: MIT */

/*
Copyright (c) 2024 Pluraf Embedded AB <code@pluraf.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to
do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "crypto/ecc-light-certificate/ecdsa.h"
#include "crypto/sha2/sha2.h"
#include "base64/base64.h"

#include "jwt.h"

#include <mosquitto.h>
#include <mosquitto_broker.h>


char* jwt_create(char * project_id, long long int time, NN_DIGIT * priv_key, int jwt_exp_secs) {
    ecc_init();  // TODO: Move to init

    char* jwt_header = malloc(1024);
    char* jwt_payload = malloc(1024);
    char* jwt_signature = malloc(1024);
    char* jwt_buff = malloc(1024);

    sprintf(jwt_header, "{\"alg\":\"%s\",\"typ\":\"JWT\"}", "ES256");
    sprintf(
        jwt_payload,
        "{\"iat\":%d,\"exp\":%d,\"aud\":\"%s\"}", time, time + jwt_exp_secs, project_id
    );

    int pos = base64_encode(jwt_buff, 1024, jwt_header, strlen(jwt_header));
    jwt_buff[pos++] = '.';
    pos += base64_encode(jwt_buff + pos, 1024, jwt_payload, strlen(jwt_payload));

    SHA256_CTX c256;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&c256);
    SHA256_Update(&c256, jwt_buff, pos);
    SHA256_Final(hash, &c256);

    point_t pub_key;
    ecc_gen_pub_key(priv_key, &pub_key);

    ecdsa_init(&pub_key);

    NN_DIGIT signature_r[NUMWORDS];
    NN_DIGIT signature_s[NUMWORDS];
    ecdsa_sign((uint8_t *)hash, signature_r, signature_s, priv_key);

    unsigned char signature[64];
    NN_Encode(signature, NUMBYTES - NN_DIGIT_LEN, signature_r, NUMWORDS - 1);
	NN_Encode(
        signature + NUMBYTES - NN_DIGIT_LEN, NUMBYTES - NN_DIGIT_LEN, signature_s, NUMWORDS - 1
    );

    jwt_buff[pos++] = '.';
    base64_encode(jwt_buff + pos, 1024, signature, 64);
    return jwt_buff;
}


int jwt_verify(char * jwt,  point_t * pub_key)
{
    //ecc_init(); // TODO: Has to be initialized only once -> move to broker init phase

    // First check if jwt is in correct format then decode
    char * dot_pos_1 = strchr(jwt, '.');
    if (!dot_pos_1) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Invalid JWT: Missing dot!");
        return 0;
    }  // dot_pos_1 = header_end

    char * dot_pos_2 = strchr(dot_pos_1 + 1, '.');
    if (!dot_pos_2) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Invalid JWT: Missing dot!");
        return 0;
    }  // dot_pos_2 = body_end

    if (strlen(dot_pos_2 + 1) < (2 * NUMBYTES)) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Invalid JWT: Signature too short!");
        return 0;
    }  // check signature length

    simple_array_t jwt_header = base64_decode(jwt, dot_pos_1 - jwt);
    simple_array_t jwt_body = base64_decode(dot_pos_1 + 1, dot_pos_2 - (dot_pos_1 + 1));
    simple_array_t jwt_signature = base64_decode(dot_pos_2 + 1, strlen(dot_pos_2 + 1));

    SHA256_CTX c256;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&c256);
    SHA256_Update(&c256, jwt, dot_pos_2 - jwt);
    SHA256_Final(hash, &c256);

    NN_DIGIT signature_r[NUMWORDS] = {};
    NN_DIGIT signature_s[NUMWORDS] = {};
  	NN_Decode(signature_r, NUMWORDS - 1, jwt_signature.data, NUMBYTES - NN_DIGIT_LEN);
	NN_Decode(signature_s, NUMWORDS - 1,
              jwt_signature.data + NUMBYTES - NN_DIGIT_LEN, NUMBYTES - NN_DIGIT_LEN
    );

    ecdsa_init(pub_key);
    return ecdsa_verify(hash, signature_r, signature_s, pub_key);
}
