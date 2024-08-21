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