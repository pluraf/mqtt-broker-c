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
#include <stdio.h>
#include <uthash.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "json_help.h"

#include "dynamic_security.h"

/* ################################################################
 * #
 * # Plugin global variables
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Function declarations
 * #
 * ################################################################ */

/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */


/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int dynsec_clientlist__cmp(void *a, void *b)
{
	struct dynsec__clientlist *clientlist_a = a;
	struct dynsec__clientlist *clientlist_b = b;

	return strcmp(clientlist_a->client->connid, clientlist_b->client->connid);
}


void dynsec_clientlist__kick_all(struct dynsec__clientlist *base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;

	HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
		if(clientlist->client->clientid){
			mosquitto_kick_client_by_clientid(clientlist->client->clientid, false);
		}else{
			mosquitto_kick_client_by_username(clientlist->client->username, false);
		}
	}
}

cJSON *dynsec_clientlist__all_to_json(struct dynsec__clientlist *base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;
	cJSON *j_clients, *j_client;

	j_clients = cJSON_CreateArray();
	if(j_clients == NULL) return NULL;

	HASH_ITER(hh, base_clientlist, clientlist, clientlist_tmp){
		j_client = cJSON_CreateObject();
		if(j_client == NULL){
			cJSON_Delete(j_clients);
			return NULL;
		}
		cJSON_AddItemToArray(j_clients, j_client);

		if(cJSON_AddStringToObject(j_client, "connid", clientlist->client->connid) == NULL
				|| (clientlist->priority != -1 && cJSON_AddIntToObject(j_client, "priority", clientlist->priority) == NULL)
				){

			cJSON_Delete(j_clients);
			return NULL;
		}
	}
	return j_clients;
}


int dynsec_clientlist__add(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client, int priority)
{
	struct dynsec__clientlist *clientlist;

	HASH_FIND(hh, *base_clientlist, client->connid, strlen(client->connid), clientlist);
	if(clientlist != NULL){
		/* Client is already in the group */
		return MOSQ_ERR_SUCCESS;
	}

	clientlist = mosquitto_malloc(sizeof(struct dynsec__clientlist));
	if(clientlist == NULL){
		return MOSQ_ERR_NOMEM;
	}

	clientlist->client = client;
	clientlist->priority = priority;
	HASH_ADD_KEYPTR_INORDER(hh, *base_clientlist, client->connid, strlen(client->connid), clientlist, dynsec_clientlist__cmp);

	return MOSQ_ERR_SUCCESS;
}


void dynsec_clientlist__cleanup(struct dynsec__clientlist **base_clientlist)
{
	struct dynsec__clientlist *clientlist, *clientlist_tmp;

	HASH_ITER(hh, *base_clientlist, clientlist, clientlist_tmp){
		HASH_DELETE(hh, *base_clientlist, clientlist);
		mosquitto_free(clientlist);
	}
}


void dynsec_clientlist__remove(struct dynsec__clientlist **base_clientlist, struct dynsec__client *client)
{
	struct dynsec__clientlist *clientlist;

	HASH_FIND(hh, *base_clientlist, client->connid, strlen(client->connid), clientlist);
	if(clientlist){
		HASH_DELETE(hh, *base_clientlist, clientlist);
		mosquitto_free(clientlist);
	}
}
