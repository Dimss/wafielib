#ifndef WAFIELIB_LIBRARY_H
#define WAFIELIB_LIBRARY_H
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
    char *config_path;
    int total_loaded_rules;
    EvaluationRequestHeader *headers;
    Transaction *transaction;
    RulesSet *rules;
    ModSecurity *modsec;
} EvaluationRequest;

void wafie_init(EvaluationRequest *request);

void wafie_cleanup(EvaluationRequest const *request);

int wafie_process_request_headers(EvaluationRequest const *request);

int wafie_process_request_body(EvaluationRequest const *request);

#endif //WAFIELIB_LIBRARY_H
