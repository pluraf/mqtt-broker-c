/* SPDX-License-Identifier: BSD-3-Clause */

/*
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
*/

/*
Contributors:
    Konstantin Tyurin <konstantin@pluraf.com>
    Gökçe Yetiser Vural <gokce@pluraf.com>
*/


#include <string.h>

#include "civetweb/civetweb.h"


static int handler(struct mg_connection * conn, void * ignored)
{
	const char *msg = "Hello world !";
	unsigned long len = (unsigned long)strlen(msg);

	mg_send_http_ok(conn, "text/plain", len);

	mg_write(conn, msg, len);

	return 200; /* HTTP state 200 = OK */
}


int auth_handler(struct mg_connection * conn, void * cbdata)
{
    int authorized = 0;

    char * auth_token = mg_get_header(conn, "Authorization");
    if(auth_token != NULL){
        ///////////////////////////////////////////////////////
        // TODO: Validate JWT TOKEN HERE
        ///////////////////////////////////////////////////////
    }

    if(authorized) {
        return 1;
    } else {
        mg_send_http_error(conn, 403, "");
        return 0;
    }
}


struct mg_context * start_server()
{
    /* Server context handle */
    struct mg_context *ctx;

    /* Initialize the library */
    mg_init_library(0);

    /* Start the server */
    ctx = mg_start(NULL, 0, NULL);

    /* Add some handler */
    mg_set_request_handler(ctx, "/home", handler, "Hello world");

    mg_set_auth_handler(ctx, "/**", auth_handler, NULL);

    return ctx;

}


void stop_server(struct mg_context * ctx)
{
    /* Stop the server */
    mg_stop(ctx);

    /* Un-initialize the library */
    mg_exit_library();
}