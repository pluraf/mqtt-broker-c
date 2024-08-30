/* SPDX-License-Identifier: BSD-3-Clause */

/******************************************************************************
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of Eclipse Distribution License v1.0
which accompany this distribution.

The Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php

Contributors:
   Roger Light - initial implementation and documentation.

******************************************************************************/

/******************************************************************************
Copyright (c) 2024 Pluraf Embedded AB <code@pluraf.com>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

===============================================================================

Contributors:
   Konstantin Tyurin <konstantin@pluraf.com>

******************************************************************************/


#include "config.h"

#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "json_help.h"
#include "mosquitto.h"


int json_get_bool(cJSON *json, const char *name, bool *value, bool optional, bool default_value)
{
    cJSON *jtmp;

    if(optional == true){
        *value = default_value;
    }

    jtmp = cJSON_GetObjectItem(json, name);
    if(jtmp){
        if(cJSON_IsBool(jtmp) == false){
            return MOSQ_ERR_INVAL;
        }
        *value = cJSON_IsTrue(jtmp);
    }else{
        if(optional == false){
            return MOSQ_ERR_INVAL;
        }
    }
    return MOSQ_ERR_SUCCESS;
}


int json_get_int(cJSON *json, const char *name, int *value, bool optional, int default_value)
{
    cJSON *jtmp;

    if(optional == true){
        *value = default_value;
    }

    jtmp = cJSON_GetObjectItem(json, name);
    if(jtmp){
        if(cJSON_IsNumber(jtmp) == false){
            return MOSQ_ERR_INVAL;
        }
        *value  = jtmp->valueint;
    }else{
        if(optional == false){
            return MOSQ_ERR_INVAL;
        }
    }
    return MOSQ_ERR_SUCCESS;
}


int json_get_string_allow_empty(cJSON *json, const char *name, char **value, bool optional)
{
    cJSON *jtmp;
    *value = NULL;

    jtmp = cJSON_GetObjectItem(json, name);
    if(jtmp){
        if(cJSON_IsString(jtmp) == false){
            return MOSQ_ERR_INVAL;
        }
        *value  = jtmp->valuestring;
        return MOSQ_ERR_SUCCESS;
    }else{
        if(optional == false){
            return MOSQ_ERR_INVAL;
        }else{
            return MOSQ_ERR_SUCCESS;
        }
    }
}


int json_get_string(cJSON *json, const char *name, char **value, bool optional)
{
    int rc = json_get_string_allow_empty(json, name, value, optional);
    if(rc == MOSQ_ERR_SUCCESS && *value != NULL && strlen(*value) == 0){
        *value = NULL;
        return MOSQ_ERR_INVAL;
    }
    return rc;
}


int json_get_object(cJSON *json, const char *name, cJSON **obj, bool optional)
{
    cJSON *jtmp;

    *obj = NULL;

    jtmp = cJSON_GetObjectItem(json, name);
    if(jtmp){
        if(cJSON_IsObject(jtmp) == false){
            return MOSQ_ERR_INVAL;
        }
        *obj  = jtmp;
    }else{
        if(optional == false){
            return MOSQ_ERR_INVAL;
        }
    }
    return MOSQ_ERR_SUCCESS;
}


cJSON *cJSON_AddIntToObject(cJSON * const object, const char * const name, int number)
{
    char buf[30];

    snprintf(buf, sizeof(buf), "%d", number);
    return cJSON_AddRawToObject(object, name, buf);
}
