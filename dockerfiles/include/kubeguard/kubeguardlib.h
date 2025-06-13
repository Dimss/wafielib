#ifndef KUBEGUARDLIB_LIBRARY_H
#define KUBEGUARDLIB_LIBRARY_H
#include <modsecurity/transaction.h>

typedef struct {
    char *client_ip;
} EvaluationRequest;

void library_init(char const *file_path);

int evaluate(EvaluationRequest const *request);

void dump_rules();

void cleanup(const char *error, RulesSet *rules, ModSecurity *modsec);

#endif //KUBEGUARDLIB_LIBRARY_H
