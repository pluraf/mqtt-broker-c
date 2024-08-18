
extern struct mg_context;

struct mg_context * start_server();
void stop_server(struct mg_context * ctx);