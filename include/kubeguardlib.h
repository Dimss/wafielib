#ifndef KUBEGUARDLIB_LIBRARY_H
#define KUBEGUARDLIB_LIBRARY_H
#include <modsecurity/transaction.h>

typedef struct {
    const unsigned char *key;
    const unsigned char *value;
} EvaluationRequestHeader;

typedef struct {
    char *client_ip;
    char *uri;
    char *http_method;
    char *http_version;
    char *body;
    size_t headers_count;
    EvaluationRequestHeader *headers;
    Transaction *transaction;
} EvaluationRequest;

void kg_library_init(char const *file_path);

int kg_process_request_headers(EvaluationRequest const *request);

void kg_init_request_transaction(EvaluationRequest *request);

void kg_dump_rules();

void kg_cleanup(const char *error, RulesSet *rules, ModSecurity *modsec);

int kg_add_rule(const char *rule);

#endif //KUBEGUARDLIB_LIBRARY_H
