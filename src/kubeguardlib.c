#include "kubeguardlib.h"

#include <stdio.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

ModSecurity *modsec;
RulesSet *rules;

void kg_library_init(char const *file_path) {
    const char *error = NULL;
    modsec = msc_init();
    msc_set_connector_info(modsec, "KubeGuard v0.0.1-alpha");
    rules = msc_create_rules_set();
    int const ret = msc_rules_add_file(rules, file_path, &error);
    if (ret < 0) {
        fprintf(stderr, "Problems loading the rules --\n");
        fprintf(stderr, "%s\n", error);
        kg_cleanup(error, rules, modsec);
    }
    msc_rules_dump(rules);
}

void kg_cleanup(const char *error, RulesSet *rules, ModSecurity *modsec) {
    if (error != NULL) {
        msc_rules_error_cleanup(error);
    }
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    exit(1);
}

ModSecurityIntervention kg_new_intervention() {
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    intervention.pause = 0;
    return intervention;
}

int kg_process_intervention(Transaction *transaction) {
    ModSecurityIntervention intervention = kg_new_intervention();
    if (msc_intervention(transaction, &intervention) == 0) {
        return 0;
    }
    if (intervention.log == NULL) {
        intervention.log = strdup("(no log message was specified)");
    }
    fprintf(stdout, "Log: %s\n", intervention.log);
    free(intervention.log);
    if (intervention.url != NULL) {
        fprintf(stdout, "Intervention, redirect to: %s\n", intervention.url);
        fprintf(stdout, " with status code: %d\n", intervention.status);
        free(intervention.url);
        intervention.url = NULL;
        return intervention.status;
    }
    if (intervention.status != 200) {
        fprintf(stdout, "Intervention, returning code: %d\n", intervention.status);
        return intervention.status;
    }
    return 0;
}

int kg_evaluate(EvaluationRequest const *request) {
    // create new transaction
    Transaction *transaction = msc_new_transaction(modsec, rules, NULL);
    int intervention_status = 0;
    // process connection
    msc_process_connection(transaction, request->client_ip, 0, "0.0.0.0", 0);
    intervention_status = kg_process_intervention(transaction);
    if (intervention_status != 0) {
        msc_transaction_cleanup(transaction);
        return intervention_status;
    }
    // process URI and request headers
    msc_process_uri(transaction, request->uri, request->http_method, request->http_version);
    intervention_status = kg_process_intervention(transaction);
    if (intervention_status != 0) {
        msc_transaction_cleanup(transaction);
        return intervention_status;
    }
    for (size_t i = 0; i < request->headers_count; i++) {
        msc_add_request_header(transaction, request->headers[i].key, request->headers[i].value);
    }
    msc_process_request_headers(transaction);
    intervention_status = kg_process_intervention(transaction);
    if (intervention_status != 0) {
        msc_transaction_cleanup(transaction);
        return intervention_status;
    }
    // cleanup transaction
    msc_transaction_cleanup(transaction);
    return 0;
}

int kg_add_rule(char const *rule) {
    const char *error = NULL;
    int const ret = msc_rules_add(rules, rule, &error);
    if (ret < 0) {
        fprintf(stderr, "problems adding the rule -- %s\n", rule);
        fprintf(stderr, "%s\n", error);
        return 1;
    }
    return 0;
}
