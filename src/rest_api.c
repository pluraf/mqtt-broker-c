#include <string.h>

#include "civetweb/civetweb.h"
#include <stdbool.h>


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
    char id;
}node_t;

typedef struct {
    char name;
    char id;
    bool is_active;
}user_t;

typedef struct {
    node_t node;
    struct node_pseudo_db_t *new_node;
}node_pseudo_db_t;

node_pseudo_db_t *p_node_db;
user_t current_user = {1, 1, "active_user"};

node_t *get_node_by_nodename(const char *node_name, int user_id) 
{
    node_pseudo_db_t *current = p_node_db;
    while (current != NULL) {
        if (strcmp(current->node.name, node_name) == 0 && current->node.client_id == user_id) {
            return &current->node;
        }
        current = current->new_node;
    }
    return NULL;
}

node_t *get_node_by_node_id_for_user(const char *node_id, int user_id) 
{
    node_pseudo_db_t *current = p_node_db;
    while (current != NULL) {
        if (strcmp(current->node.id, node_id) == 0 && current->node.client_id == user_id) {
            return &current->node;
        }
        current = current->new_node;
    }
    return NULL;
}

node_t *create_node(const char *node_name, const char *node_id, int user_id) 
{
    node_pseudo_db_t *new_entry = (node_pseudo_db_t *)malloc(sizeof(node_pseudo_db_t));
    if (!new_entry) {
        return NULL;  // Memory allocation failed
    }

    strcpy(new_entry->node.name, node_name);
    strcpy(new_entry->node.id, node_id);
    new_entry->node.client_id = user_id;
    new_entry->new_node = p_node_db;
    p_node_db = new_entry;

    return &new_entry->node;
}

static int node_create_handler(struct mg_connection *conn, void *ignored)
{
    node_t node;
    user_t user;
    node_pseudo_db_t *new_node;
    char post_data;

    int data_len = mg_read(conn, post_data, sizeof(post_data));

    if(data_len <= 0){
        mg_printf(conn,
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Failed to read data\n");
        return 400;
    }

    mg_get_var(post_data, data_len, "node name", node.name, sizeof(node.name));
    mg_get_var(post_data, data_len, "auth_type", node.auth_type, sizeof(node.auth_type));
    mg_get_var(post_data, data_len, "password", node.password, sizeof(node.password));
    mg_get_var(post_data, data_len, "node_id", node.id, sizeof(node.id));

    if(!user.is_active){
        mg_printf(conn,
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Only active users are authorized\n");
        return 400;
    }

    new_node = get_node_by_nodename(node.name, current_user.id);
    if(p_node_db != NULL){
        mg_printf(conn,
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Node id already registered\n");
        return 400;
    }

    new_node = create_node(node.name, node.id, current_user.id);
    if (new_node == NULL) {
        mg_printf(conn,
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Invalid registry id\n");
        return 400;
    }

    mg_printf(conn,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "Node created successfully\n");

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
    mg_set_request_handler(ctx, "user/create", node_create_handler, NULL);

    return ctx;

}


void stop_server(struct mg_context * ctx)
{
    /* Stop the server */
    mg_stop(ctx);

    /* Un-initialize the library */
    mg_exit_library();
}