#include <string.h>

#include "civetweb/civetweb.h"


static int handler(struct mg_connection *conn, void *ignored)
{
	const char *msg = "Hello world !";
	unsigned long len = (unsigned long)strlen(msg);

	mg_send_http_ok(conn, "text/plain", len);

	mg_write(conn, msg, len);

	return 200; /* HTTP state 200 = OK */
}

typedef enum {
    MQTT_AUTH_PASSWORD,
    MQTT_AUTH_JWT_ES256,
    MQTT_AUTH_JWT_RS256,
    MQTT_AUTH_INVALID
} mqtt_auth_t;

typedef struct {
    char *name;
    char *client_id;
    mqtt_auth_t *auth_type;
    char *password;
}node_t;

static int node_handler(struct mg_connection *conn, void *ignored)
{
    node_t node;

    mg_get_var(conn, "node name", node.name, sizeof(node.name));
    mg_get_var(conn, "auth_type", node.auth_type, sizeof(node.auth_type));
    mg_get_var(conn, "password", node.password, sizeof(node.password));

    return 200;
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
    mg_set_request_handler(ctx, "/hello", handler, "Hello world");

    return ctx;

}


void stop_server(struct mg_context * ctx)
{
    /* Stop the server */
    mg_stop(ctx);

    /* Un-initialize the library */
    mg_exit_library();
}