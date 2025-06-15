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
    const unsigned char *body;
    size_t headers_count;
    EvaluationRequestHeader *headers;
} EvaluationRequest;

void kg_library_init(char const *file_path);

int kg_evaluate(EvaluationRequest const *request);

void kg_dump_rules();

void kg_cleanup(const char *error, RulesSet *rules, ModSecurity *modsec);

int kg_add_rule(const char *rule);

#endif //KUBEGUARDLIB_LIBRARY_H
