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
 * # Function declarations
 * #
 * ################################################################ */

static int dynsec__remove_client_from_all_groups(struct dynsec__client * client);
static void client__remove_all_roles(struct dynsec__client * client);

/* ################################################################
 * #
 * # Local variables
 * #
 * ################################################################ */

static struct dynsec__client * local_username_clients = NULL;
static struct dynsec__client * local_clientid_clients = NULL;
static struct dynsec__client * local_connectors = NULL;

/* ################################################################
 * #
 * # Utility functions
 * #
 * ################################################################ */

static int client_cmp_by_connid(void *a, void *b)
{
	struct dynsec__client *client_a = a;
	struct dynsec__client *client_b = b;

	return strcmp(client_a->connid, client_b->connid);
}

static int client_cmp_by_clientid(void *a, void *b)
{
	struct dynsec__client *client_a = a;
	struct dynsec__client *client_b = b;

	return strcmp(client_a->clientid, client_b->clientid);
}

static int client_cmp_by_username(void *a, void *b)
{
	struct dynsec__client *client_a = a;
	struct dynsec__client *client_b = b;

	return strcmp(client_a->username, client_b->username);
}


int dynsec_clients__add_check_uniqueness(const struct dynsec__client *client) {
	struct dynsec__client * existing = NULL;

	HASH_FIND(hh, local_connectors, client->connid, strlen(client->connid), existing);
	if (existing) return MOSQ_ERR_ALREADY_EXISTS;

	if(client->clientid){
		HASH_FIND(hh_clientid, local_clientid_clients, client->clientid, strlen(client->clientid), existing);
		if (existing) return MOSQ_ERR_ALREADY_EXISTS;
	}else if(client->username){
		HASH_FIND(hh_username, local_username_clients, client->username, strlen(client->username), existing);
		if (existing) return MOSQ_ERR_ALREADY_EXISTS;
	}

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__add_inorder(struct dynsec__client *client)
{
	if(dynsec_clients__add_check_uniqueness(client) == MOSQ_ERR_SUCCESS){
		HASH_ADD_KEYPTR_INORDER(hh, local_connectors, client->connid, strlen(client->connid), client, client_cmp_by_connid);
		if(client->clientid){
			HASH_ADD_KEYPTR_INORDER(hh_clientid, local_clientid_clients, client->clientid, strlen(client->clientid), client, client_cmp_by_clientid);
		}else if(client->username){
			HASH_ADD_KEYPTR_INORDER(hh_username, local_username_clients, client->username, strlen(client->username), client, client_cmp_by_username);
		}
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_ALREADY_EXISTS;
}


int dynsec_clients__add(struct dynsec__client *client)
{
	if(dynsec_clients__add_check_uniqueness(client) == MOSQ_ERR_SUCCESS){
		HASH_ADD_KEYPTR(hh, local_connectors, client->connid, strlen(client->connid), client);
		if(client->clientid){
			HASH_ADD_KEYPTR(hh_clientid, local_clientid_clients, client->clientid, strlen(client->clientid), client);
		}else if(client->username){
			HASH_ADD_KEYPTR(hh_username, local_username_clients, client->username, strlen(client->username), client);
		}
		return MOSQ_ERR_SUCCESS;
	}
	return MOSQ_ERR_ALREADY_EXISTS;
}


struct dynsec__client * dynsec_clients__find(const char *clientid, const char *username)
{
	struct dynsec__client *client = NULL;

	if(clientid){
		HASH_FIND(hh_clientid, local_clientid_clients, clientid, strlen(clientid), client);
	}else if(username){
		HASH_FIND(hh_username, local_username_clients, username, strlen(username), client);
	}
	return client;
}

struct dynsec__client *dynsec_clients__get(const char * connid)
{
	struct dynsec__client *client = NULL;
	if(connid) HASH_FIND(hh, local_connectors, connid, strlen(connid), client);
	return client;
}


static void client__unallocate_item(struct dynsec__client *client)
{
	if (client->rolelist) dynsec_rolelist__cleanup(&client->rolelist);
	if (client->grouplist) dynsec__remove_client_from_all_groups(client);
	mosquitto_free(client->text_name);
	mosquitto_free(client->text_description);
	mosquitto_free(client->clientid);
	mosquitto_free(client->username);
	mosquitto_free(client->jwtkey);
	mosquitto_free(client->connid);
	mosquitto_free(client->authtype);
	mosquitto_free(client);
}


static void client__free_item(struct dynsec__client *client)
{
	struct dynsec__client *client_found;
	if(client == NULL) return;

	client_found = dynsec_clients__get(client->connid);
	if(client_found){
		HASH_DELETE(hh,local_connectors, client_found);
		if(client->clientid){
			HASH_DELETE(hh_clientid, local_clientid_clients, client_found);
		}else if(client->username){
			HASH_DELETE(hh_username, local_username_clients, client_found);
		}
	}
	client__unallocate_item(client);
}


void dynsec_clients__cleanup(void)
{
	struct dynsec__client *client, *client_tmp;

	HASH_ITER(hh, local_connectors, client, client_tmp){
		client__free_item(client);
	}

	HASH_ITER(hh_clientid, local_clientid_clients, client, client_tmp){
		client__free_item(client);
	}
	HASH_ITER(hh_username, local_username_clients, client, client_tmp){
		client__free_item(client);
	}
}


void dynsec_clients__kick_clients(struct dynsec__client *client)
{
	if (client) {
		if(client->clientid){
			mosquitto_kick_client_by_clientid(client->clientid, false);
		}else if(client->username){
			mosquitto_kick_client_by_username(client->username, false);
		}
	}
}


/* ################################################################
 * #
 * # Config file load and save
 * #
 * ################################################################ */

int dynsec_clients__config_load(cJSON *tree)
{
	cJSON *j_clients, *j_client, *j_roles, *j_role, *j_password;
	struct dynsec__client *client;
	struct dynsec__role *role;
	unsigned char *buf;
	int buf_len;
	int priority;

	j_clients = cJSON_GetObjectItem(tree, "clients");
	if(j_clients == NULL){
		return 0;
	}

	if(cJSON_IsArray(j_clients) == false){
		return 1;
	}

	cJSON_ArrayForEach(j_client, j_clients){
		if(cJSON_IsObject(j_client) == true){
			// connid
			char *connid;
 			json_get_string(j_client, "connid", &connid, false);
			if(! connid)continue;

			// username
			char *username;
			json_get_string(j_client, "username", &username, false);

			// clientid
			char *clientid;
			json_get_string(j_client, "clientid", &clientid, false);

			client = dynsec_clients__find(clientid, username);
			if(client)continue;

			// Create client
			client = mosquitto_calloc(1, sizeof(struct dynsec__client));
			if(client == NULL){
				return MOSQ_ERR_NOMEM;
			}
			client->connid = mosquitto_strdup(connid);
			if(client->connid == NULL){
				client__unallocate_item(client);
				continue;
			}
			if(clientid){
				client->clientid = mosquitto_strdup(clientid);
				if(client->clientid == NULL){
					client__unallocate_item(client);
					continue;
				}
			}
			if(username){
				client->username = mosquitto_strdup(username);
				if(client->username == NULL){
					client__unallocate_item(client);
					continue;
				}
			}

			// Time to check for uniqueness
			if(dynsec_clients__add(client) != MOSQ_ERR_SUCCESS){
				client__unallocate_item(client);
				continue;
			}

			bool disabled;
			if(json_get_bool(j_client, "disabled", &disabled, false, false) == MOSQ_ERR_SUCCESS){
				client->disabled = disabled;
			}

			// Password
			if(json_get_object(j_client, "password", &j_password, true), j_password){
				char *salt, *password;
				int iterations;
				json_get_string(j_password, "salt", &salt, false);
				json_get_string(j_password, "hash", &password, false);
				json_get_int(j_password, "iterations", &iterations, false, -1);

				if(salt && password && iterations > 0){
					client->pw.iterations = iterations;

					if(dynsec_auth__base64_decode(salt, &buf, &buf_len) != MOSQ_ERR_SUCCESS
							|| buf_len != sizeof(client->pw.salt)){
						client__unallocate_item(client);
						continue;
					}
					memcpy(client->pw.salt, buf, (size_t)buf_len);
					mosquitto_free(buf);

					if(dynsec_auth__base64_decode(password, &buf, &buf_len) != MOSQ_ERR_SUCCESS
							|| buf_len != sizeof(client->pw.password_hash)){
						client__unallocate_item(client);
						continue;
					}
					memcpy(client->pw.password_hash, buf, (size_t)buf_len);
					mosquitto_free(buf);
					client->pw.valid = true;
				}else{
					client->pw.valid = false;
				}
			}

			// JWT key
			char * jwtkey;
			if(json_get_string(j_client, "password", &jwtkey, true), jwtkey){
				client->jwtkey = mosquitto_strdup(jwtkey);
				if(client->jwtkey == NULL){
					client__unallocate_item(client);
					continue;
				}
			}

			/* Text name */
			char *textname;
			json_get_string(j_client, "textname", &textname, false);
			if(textname){
				client->text_name = mosquitto_strdup(textname);
				if(client->text_name == NULL){
					client__unallocate_item(client);
					continue;
				}
			}

			/* Text description */
			char *textdescription;
			json_get_string(j_client, "textdescription", &textdescription, false);
			if(textdescription){
				client->text_description = mosquitto_strdup(textdescription);
				if(client->text_description == NULL){
					client__unallocate_item(client);
					continue;
				}
			}

			/* Roles */
			j_roles = cJSON_GetObjectItem(j_client, "roles");
			if(j_roles && cJSON_IsArray(j_roles)){
				cJSON_ArrayForEach(j_role, j_roles){
					if(cJSON_IsObject(j_role)){
						char *rolename;
						json_get_string(j_role, "rolename", &rolename, false);
						if(rolename){
							json_get_int(j_role, "priority", &priority, true, -1);
							role = dynsec_roles__find(rolename);
							dynsec_rolelist__client_add(client, role, priority);
						}
					}
				}
			}
			printf("add: %s\n", client->connid);
		}
	}

	HASH_SRT(hh, local_connectors, client_cmp_by_connid);
	HASH_SRT(hh_clientid, local_clientid_clients, client_cmp_by_clientid);
	HASH_SRT(hh_username, local_username_clients, client_cmp_by_username);

	return 0;
}


static int dynsec__config_add_clients(cJSON *j_clients, struct dynsec__client * local_clients)
{
	struct dynsec__client *client, *client_tmp;
	cJSON *j_client, *j_roles, *jtmp;
	char *buf;

	HASH_ITER(hh, local_clients, client, client_tmp){
		j_client = cJSON_CreateObject();
		if(j_client == NULL) return 1;
		cJSON_AddItemToArray(j_clients, j_client);

		if((client->connid && cJSON_AddStringToObject(j_client, "connid", client->connid) == NULL)
				|| (client->username && (cJSON_AddStringToObject(j_client, "username", client->username) == NULL))
				|| (client->clientid && (cJSON_AddStringToObject(j_client, "clientid", client->clientid) == NULL))
				|| (client->text_name && (cJSON_AddStringToObject(j_client, "textname", client->text_name) == NULL))
				|| (client->text_description && (cJSON_AddStringToObject(j_client, "textdescription", client->text_description) == NULL))
				|| (client->disabled && (cJSON_AddBoolToObject(j_client, "disabled", true) == NULL))){
			return 1;
		}

		// Add roles
		j_roles = dynsec_rolelist__all_to_json(client->rolelist);
		if(j_roles == NULL){
			return 1;
		}
		cJSON_AddItemToObject(j_client, "roles", j_roles);

		// Add password
		if(client->pw.valid){
			cJSON * j_password = cJSON_CreateObject();

			// password hash
			if(dynsec_auth__base64_encode(client->pw.password_hash, sizeof(client->pw.password_hash), &buf) != MOSQ_ERR_SUCCESS){
				return 1;
			}
			jtmp = cJSON_CreateString(buf);
			mosquitto_free(buf);
			if(jtmp == NULL) return 1;
			cJSON_AddItemToObject(j_password, "hash", jtmp);

			// password salt
			if(dynsec_auth__base64_encode(client->pw.salt, sizeof(client->pw.salt), &buf) != MOSQ_ERR_SUCCESS){
				return 1;
			}
			jtmp = cJSON_CreateString(buf);
			mosquitto_free(buf);
			if(jtmp == NULL) return 1;
			cJSON_AddItemToObject(j_password, "salt", jtmp);

			// password iterations
			if(cJSON_AddIntToObject(j_password, "iterations", client->pw.iterations) == NULL){
				return 1;
			}

			cJSON_AddItemToObject(j_client, "password", j_password);
		}

		// Add JWT public key
		if(client->jwtkey && cJSON_AddStringToObject(j_client, "jwtkey", client->jwtkey) == NULL){
			return 1;
		}
	}

	return 0;
}


int dynsec_clients__config_save(cJSON *tree)
{
	cJSON *j_clients;

	if((j_clients = cJSON_AddArrayToObject(tree, "clients")) == NULL) return 1;
	if(dynsec__config_add_clients(j_clients, local_connectors)) return 1;

	return 0;
}


int dynsec_clients__process_create(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *username, *password, *clientid, *connid;
	char *text_name, *text_description, *authtype;
	struct dynsec__client *client;
	int rc;
	cJSON *j_groups, *j_group;
	int priority;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	// Check the client doesn't exist already
	client = dynsec_clients__get(connid);
	if(client){
		dynsec__command_reply(j_responses, context, "createClient", "Client already exists", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	if(json_get_string(command, "username", &username, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "clientid", &clientid, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing clientid", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	// Either clientid or username (or both) has to be set
	if(username == NULL && clientid == NULL) {
		dynsec__command_reply(j_responses, context, "createClient", "Missing both clientid and username", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	// Check username and clientid are valid UTF8
	if(username && mosquitto_validate_utf8(username, (int)strlen(username)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(clientid && mosquitto_validate_utf8(clientid, (int)strlen(clientid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Client ID not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "authtype", &authtype, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing authtype", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "password", &password, strcmp(authtype, MQTT_AUTH_NONE) == 0) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing password", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textname", &text_name, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing textname", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "textdescription", &text_description, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "createClient", "Invalid/missing textdescription", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	// Create client
	client = mosquitto_calloc(1, sizeof(struct dynsec__client));
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	client->connid = mosquitto_strdup(connid);
	if(client->connid == NULL){
		dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		client__free_item(client);
		return MOSQ_ERR_NOMEM;
	}

	if(username){
		client->username = mosquitto_strdup(username);
		if(client->username == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}

	if(clientid){
		client->clientid = mosquitto_strdup(clientid);
		if(client->clientid == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}

	// Time to check for uniqueness
	// (must add user before groups, otherwise adding groups will fail)
	if(dynsec_clients__add_inorder(client) != MOSQ_ERR_SUCCESS){
		client__unallocate_item(client);
		dynsec__command_reply(j_responses, context, "createClient", "Connector ambiguous", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	if (client->authtype = mosquitto_strdup(authtype), ! client->authtype){
		dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		client__free_item(client);
		return MOSQ_ERR_NOMEM;
	}

	if (strcmp(client->authtype, MQTT_AUTH_PASSWORD)){
		if(dynsec_auth__pw_hash(client, password, client->pw.password_hash, sizeof(client->pw.password_hash), true)){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
		client->pw.valid = true;
	}else if(strncmp(MQTT_AUTH_KEY_PREFIX, client->authtype, strlen(MQTT_AUTH_KEY_PREFIX)) == 0){
		client->jwtkey = mosquitto_strdup(password);
	}

	if(text_name){
		client->text_name = mosquitto_strdup(text_name);
		if(client->text_name == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}

	if(text_description){
		client->text_description = mosquitto_strdup(text_description);
		if(client->text_description == NULL){
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
			client__free_item(client);
			return MOSQ_ERR_NOMEM;
		}
	}

	rc = dynsec_rolelist__load_from_json(command, &client->rolelist);
	if(rc == MOSQ_ERR_SUCCESS || rc == ERR_LIST_NOT_FOUND){
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "createClient", "Role not found", correlation_data);
		client__free_item(client);
		return MOSQ_ERR_INVAL;
	}else{
		if(rc == MOSQ_ERR_INVAL){
			dynsec__command_reply(j_responses, context, "createClient", "'roles' not an array or missing/invalid rolename", correlation_data);
		}else{
			dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
		}
		client__free_item(client);
		return MOSQ_ERR_INVAL;
	}

	j_groups = cJSON_GetObjectItem(command, "groups");
	if(j_groups && cJSON_IsArray(j_groups)){
		cJSON_ArrayForEach(j_group, j_groups){
			if(cJSON_IsObject(j_group)){
				char *groupname;
				json_get_string(j_group, "groupname", &groupname, false);
				if(groupname){
					json_get_int(j_group, "priority", &priority, true, -1);
					rc = dynsec_groups__add_client(client, groupname, priority, false);
					if(rc == ERR_GROUP_NOT_FOUND){
						dynsec__command_reply(j_responses, context, "createClient", "Group not found", correlation_data);
						client__free_item(client);
						return MOSQ_ERR_INVAL;
					}else if(rc != MOSQ_ERR_SUCCESS){
						dynsec__command_reply(j_responses, context, "createClient", "Internal error", correlation_data);
						client__free_item(client);
						return MOSQ_ERR_INVAL;
					}
				}
			}
		}
	}

	dynsec__config_save();

	dynsec__command_reply(j_responses, context, "createClient", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | createClient | username=%s | password=%s",
			admin_clientid, admin_username, username, password?"*****":"no password");

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_delete(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid;
	struct dynsec__client *client;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "deleteClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__get(connid);
	if(client){
		dynsec__remove_client_from_all_groups(client);
		client__remove_all_roles(client);
		client__free_item(client);
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "deleteClient", NULL, correlation_data);

		/* Enforce any changes */
		dynsec_clients__kick_clients(client);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | deleteClient | connid=%s",
				admin_clientid, admin_username, connid);

		return MOSQ_ERR_SUCCESS;
	}else{
		dynsec__command_reply(j_responses, context, "deleteClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
}


int dynsec_clients__process_disable(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid;
	struct dynsec__client *client;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "disableClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "disableClient", "Username not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "disableClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	client->disabled = true;

	dynsec_clients__kick_clients(client);

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "disableClient", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | disableClient | connid=%s",
			admin_clientid, admin_username, connid);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_enable(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid;
	struct dynsec__client *client;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "enableClient", "Invalid/missing username", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "enableClient", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "enableClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	client->disabled = false;

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "enableClient", NULL, correlation_data);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | enableClient | username=%s",
			admin_clientid, admin_username, connid);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_set_id(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid, *clientid, *clientid_heap = NULL;
	struct dynsec__client *client;
	size_t slen;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientId", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientId", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "clientid", &clientid, true) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientId", "Invalid/missing client ID", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(clientid){
		slen = strlen(clientid);
		if(mosquitto_validate_utf8(clientid, (int)slen) != MOSQ_ERR_SUCCESS){
			dynsec__command_reply(j_responses, context, "setClientId", "Client ID not valid UTF-8", correlation_data);
			return MOSQ_ERR_INVAL;
		}
		if(slen > 0){
			clientid_heap = mosquitto_strdup(clientid);
			if(clientid_heap == NULL){
				dynsec__command_reply(j_responses, context, "setClientId", "Internal error", correlation_data);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			clientid_heap = NULL;
		}
	}

	client = dynsec_clients__get(connid);
	if(client == NULL){
		mosquitto_free(clientid_heap);
		dynsec__command_reply(j_responses, context, "setClientId", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	mosquitto_free(client->clientid);
	client->clientid = clientid_heap;

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "setClientId", NULL, correlation_data);

	/* Enforce any changes */
	dynsec_clients__kick_clients(client);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setClientId | connid=%s | clientid=%s",
			admin_clientid, admin_username, connid, client->clientid);

	return MOSQ_ERR_SUCCESS;
}


static int client__set_password(struct dynsec__client *client, const char *password)
{
	if(dynsec_auth__pw_hash(client, password, client->pw.password_hash, sizeof(client->pw.password_hash), true) == MOSQ_ERR_SUCCESS){
		client->pw.valid = true;

		return MOSQ_ERR_SUCCESS;
	}else{
		client->pw.valid = false;
		/* FIXME - this should fail safe without modifying the existing password */
		return MOSQ_ERR_NOMEM;
	}
}

int dynsec_clients__process_set_password(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid, *password;
	struct dynsec__client *client;
	int rc;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientPassword", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "password", &password, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Invalid/missing password", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(strlen(password) == 0){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Empty password is not allowed", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "setClientPassword", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}
	rc = client__set_password(client, password);
	if(rc == MOSQ_ERR_SUCCESS){
		dynsec__config_save();
		dynsec__command_reply(j_responses, context, "setClientPassword", NULL, correlation_data);

		/* Enforce any changes */
		dynsec_clients__kick_clients(client);

		admin_clientid = mosquitto_client_id(context);
		admin_username = mosquitto_client_username(context);
		mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | setClientPassword | connid=%s | password=******",
				admin_clientid, admin_username, connid);
	}else{
		dynsec__command_reply(j_responses, context, "setClientPassword", "Internal error", correlation_data);
	}
	return rc;
}


static void client__add_new_roles(struct dynsec__client *client, struct dynsec__rolelist *base_rolelist)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;

	HASH_ITER(hh, base_rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__client_add(client, rolelist->role, rolelist->priority);
	}
}

static void client__remove_all_roles(struct dynsec__client *client)
{
	struct dynsec__rolelist *rolelist, *rolelist_tmp;

	HASH_ITER(hh, client->rolelist, rolelist, rolelist_tmp){
		dynsec_rolelist__client_remove(client, rolelist->role);
	}
}

int dynsec_clients__process_modify(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid;
	char *clientid = NULL;
	char *password = NULL;
	char *text_name = NULL, *text_description = NULL;
	bool have_clientid = false, have_text_name = false, have_text_description = false, have_rolelist = false, have_password = false;
	struct dynsec__client *client;
	struct dynsec__group *group;
	struct dynsec__rolelist *rolelist = NULL;
	char *str;
	int rc;
	int priority;
	cJSON *j_group, *j_groups;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyClient", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "modifyClient", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "modifyClient", "Client not found", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "clientid", &str, false) == MOSQ_ERR_SUCCESS){
		have_clientid = true;
		if(str && strlen(str) > 0){
			clientid = mosquitto_strdup(str);
			if(clientid == NULL){
				dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
				rc = MOSQ_ERR_NOMEM;
				goto error;
			}
		}else{
			clientid = NULL;
		}
	}

	if(json_get_string(command, "password", &password, false) == MOSQ_ERR_SUCCESS){
		if(strlen(password) > 0){
			have_password = true;
		}
	}

	if(json_get_string(command, "textname", &str, false) == MOSQ_ERR_SUCCESS){
		have_text_name = true;
		text_name = mosquitto_strdup(str);
		if(text_name == NULL){
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	if(json_get_string(command, "textdescription", &str, false) == MOSQ_ERR_SUCCESS){
		have_text_description = true;
		text_description = mosquitto_strdup(str);
		if(text_description == NULL){
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	rc = dynsec_rolelist__load_from_json(command, &rolelist);
	if(rc == MOSQ_ERR_SUCCESS){
		have_rolelist = true;
	}else if(rc == ERR_LIST_NOT_FOUND){
		/* There was no list in the JSON, so no modification */
	}else if(rc == MOSQ_ERR_NOT_FOUND){
		dynsec__command_reply(j_responses, context, "modifyClient", "Role not found", correlation_data);
		rc = MOSQ_ERR_INVAL;
		goto error;
	}else{
		if(rc == MOSQ_ERR_INVAL){
			dynsec__command_reply(j_responses, context, "modifyClient", "'roles' not an array or missing/invalid rolename", correlation_data);
		}else{
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
		}
		rc = MOSQ_ERR_INVAL;
		goto error;
	}

	j_groups = cJSON_GetObjectItem(command, "groups");
	if(j_groups && cJSON_IsArray(j_groups)){
		/* Iterate through list to check all groups are valid */
		cJSON_ArrayForEach(j_group, j_groups){
			if(cJSON_IsObject(j_group)){
				char *groupname;
				json_get_string(j_group, "groupname", &groupname, false);
				if(groupname){
					group = dynsec_groups__find(groupname);
					if(group == NULL){
						dynsec__command_reply(j_responses, context, "modifyClient", "'groups' contains an object with a 'groupname' that does not exist", correlation_data);
						rc = MOSQ_ERR_INVAL;
						goto error;
					}
				}else{
					dynsec__command_reply(j_responses, context, "modifyClient", "'groups' contains an object with an invalid 'groupname'", correlation_data);
					rc = MOSQ_ERR_INVAL;
					goto error;
				}
			}
		}

		dynsec__remove_client_from_all_groups(client);
		cJSON_ArrayForEach(j_group, j_groups){
			if(cJSON_IsObject(j_group)){
				char *groupname;
				json_get_string(j_group, "groupname", &groupname, false);
				if(groupname){
					json_get_int(j_group, "priority", &priority, true, -1);
					dynsec_groups__add_client(client, groupname, priority, false);
				}
			}
		}
	}

	if(have_password){
		/* FIXME - This is the one call that will result in modification on internal error - note that groups have already been modified */
		rc = client__set_password(client, password);
		if(rc != MOSQ_ERR_SUCCESS){
			dynsec__command_reply(j_responses, context, "modifyClient", "Internal error", correlation_data);
			dynsec_clients__kick_clients(client);
			/* If this fails we have the situation that the password is set as
			 * invalid, but the config isn't saved, so restarting the broker
			 * *now* will mean the client can log in again. This might be
			 * "good", but is inconsistent, so save the config to be
			 * consistent. */
			dynsec__config_save();
			rc = MOSQ_ERR_NOMEM;
			goto error;
		}
	}

	if(have_clientid){
		mosquitto_free(client->clientid);
		client->clientid = clientid;
	}

	if(have_text_name){
		mosquitto_free(client->text_name);
		client->text_name = text_name;
	}

	if(have_text_description){
		mosquitto_free(client->text_description);
		client->text_description = text_description;
	}

	if(have_rolelist){
		client__remove_all_roles(client);
		client__add_new_roles(client, rolelist);
		dynsec_rolelist__cleanup(&rolelist);
	}

	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "modifyClient", NULL, correlation_data);

	/* Enforce any changes */
	dynsec_clients__kick_clients(client);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | modifyClient | connid=%s",
			admin_clientid, admin_username, connid);
	return MOSQ_ERR_SUCCESS;
error:
	mosquitto_free(clientid);
	mosquitto_free(text_name);
	mosquitto_free(text_description);
	dynsec_rolelist__cleanup(&rolelist);
	return rc;
}


static int dynsec__remove_client_from_all_groups(struct dynsec__client * client)
{
	struct dynsec__grouplist *grouplist, *grouplist_tmp;

	if(client){
		HASH_ITER(hh, client->grouplist, grouplist, grouplist_tmp){
			dynsec_groups__remove_client(client->connid, grouplist->group->groupname, false);
		}
	}

	return MOSQ_ERR_SUCCESS;
}


static cJSON *add_client_to_json(struct dynsec__client *client, bool verbose)
{
	cJSON *j_client = NULL, *j_groups, *j_roles;

	if(verbose){
		j_client = cJSON_CreateObject();
		if(j_client == NULL){
			return NULL;
		}

		if(cJSON_AddStringToObject(j_client, "connid", client->connid) == NULL
				|| (client->username && (cJSON_AddStringToObject(j_client, "username", client->username) == NULL))
				|| (client->clientid && (cJSON_AddStringToObject(j_client, "clientid", client->clientid) == NULL))
				|| (client->text_name && (cJSON_AddStringToObject(j_client, "textname", client->text_name) == NULL))
				|| (client->text_description && (cJSON_AddStringToObject(j_client, "textdescription", client->text_description) == NULL))
				|| (client->disabled && (cJSON_AddBoolToObject(j_client, "disabled", client->disabled) == NULL))){
			cJSON_Delete(j_client);
			return NULL;
		}

		j_roles = dynsec_rolelist__all_to_json(client->rolelist);
		if(j_roles == NULL){
			cJSON_Delete(j_client);
			return NULL;
		}
		cJSON_AddItemToObject(j_client, "roles", j_roles);

		j_groups = dynsec_grouplist__all_to_json(client->grouplist);
		if(j_groups == NULL){
			cJSON_Delete(j_client);
			return NULL;
		}
		cJSON_AddItemToObject(j_client, "groups", j_groups);
	}else{
		j_client = cJSON_CreateString(client->connid);
		if(j_client == NULL){
			return NULL;
		}
	}
	return j_client;
}


int dynsec_clients__process_get(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid;
	struct dynsec__client *client;
	cJSON *tree, *j_client, *j_data;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getClient", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "getClient", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "getClient", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "getClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	if(cJSON_AddStringToObject(tree, "command", "getClient") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	j_client = add_client_to_json(client, true);
	if(j_client == NULL){
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "getClient", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_data, "client", j_client);
	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | getClient | connid=%s",
			admin_clientid, admin_username, connid);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_list(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	bool verbose;
	struct dynsec__client *client, *client_tmp;
	cJSON *tree, *j_clients, *j_client, *j_data;
	int i, count, offset;
	const char *admin_clientid, *admin_username;

	json_get_bool(command, "verbose", &verbose, true, false);
	json_get_int(command, "count", &count, true, -1);
	json_get_int(command, "offset", &offset, true, 0);

	tree = cJSON_CreateObject();
	if(tree == NULL){
		dynsec__command_reply(j_responses, context, "listClients", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	int connectors_count = HASH_CNT(hh_clientid, local_clientid_clients) + HASH_CNT(hh_username, local_username_clients);

	if(cJSON_AddStringToObject(tree, "command", "listClients") == NULL
			|| (j_data = cJSON_AddObjectToObject(tree, "data")) == NULL
			|| cJSON_AddIntToObject(j_data, "totalCount", connectors_count) == NULL
			|| (j_clients = cJSON_AddArrayToObject(j_data, "clients")) == NULL
			|| (correlation_data && cJSON_AddStringToObject(tree, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, context, "listClients", "Internal error", correlation_data);
		return MOSQ_ERR_NOMEM;
	}

	i = 0;
	HASH_ITER(hh, local_connectors, client, client_tmp){
		if(i>=offset){
			j_client = add_client_to_json(client, verbose);
			if(j_client == NULL){
				cJSON_Delete(tree);
				dynsec__command_reply(j_responses, context, "listClients", "Internal error", correlation_data);
				return MOSQ_ERR_NOMEM;
			}
			cJSON_AddItemToArray(j_clients, j_client);

			if(count >= 0){
				count--;
				if(count <= 0){
					break;
				}
			}
		}
		i++;
	}

	cJSON_AddItemToArray(j_responses, tree);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | listClients | verbose=%s | count=%d | offset=%d",
			admin_clientid, admin_username, verbose?"true":"false", count, offset);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_add_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid, *rolename;
	struct dynsec__client *client;
	struct dynsec__role *role;
	int priority;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	json_get_int(command, "priority", &priority, true, -1);

	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "addClientRole", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "addClientRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	if(dynsec_rolelist__client_add(client, role, priority) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "addClientRole", "Internal error", correlation_data);
		return MOSQ_ERR_UNKNOWN;
	}
	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "addClientRole", NULL, correlation_data);

	/* Enforce any changes */
	dynsec_clients__kick_clients(client);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | addClientRole | connid=%s | rolename=%s | priority=%d",
			admin_clientid, admin_username, connid, rolename, priority);

	return MOSQ_ERR_SUCCESS;
}


int dynsec_clients__process_remove_role(cJSON *j_responses, struct mosquitto *context, cJSON *command, char *correlation_data)
{
	char *connid, *rolename;
	struct dynsec__client *client;
	struct dynsec__role *role;
	const char *admin_clientid, *admin_username;

	if(json_get_string(command, "connid", &connid, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Invalid/missing connid", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(connid, (int)strlen(connid)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "connid not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}

	if(json_get_string(command, "rolename", &rolename, false) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Invalid/missing rolename", correlation_data);
		return MOSQ_ERR_INVAL;
	}
	if(mosquitto_validate_utf8(rolename, (int)strlen(rolename)) != MOSQ_ERR_SUCCESS){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Role name not valid UTF-8", correlation_data);
		return MOSQ_ERR_INVAL;
	}


	client = dynsec_clients__get(connid);
	if(client == NULL){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Client not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	role = dynsec_roles__find(rolename);
	if(role == NULL){
		dynsec__command_reply(j_responses, context, "removeClientRole", "Role not found", correlation_data);
		return MOSQ_ERR_SUCCESS;
	}

	dynsec_rolelist__client_remove(client, role);
	dynsec__config_save();
	dynsec__command_reply(j_responses, context, "removeClientRole", NULL, correlation_data);

	/* Enforce any changes */
	dynsec_clients__kick_clients(client);

	admin_clientid = mosquitto_client_id(context);
	admin_username = mosquitto_client_username(context);
	mosquitto_log_printf(MOSQ_LOG_INFO, "dynsec: %s/%s | removeClientRole | connid=%s | rolename=%s",
			admin_clientid, admin_username, connid, rolename);

	return MOSQ_ERR_SUCCESS;
}
