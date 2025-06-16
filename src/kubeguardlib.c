#include "kubeguardlib.h"

#include <stdio.h>
#include <dirent.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

ModSecurity *modsec;
RulesSet *rules;


void load_rules_files(const char *config_path) {
    const char *rules_load_error = NULL;
    const char *config_file_suffix = ".conf";
    struct dirent *entry;
    DIR *dp = opendir(config_path);
    if (dp == NULL) {
        perror("opendir");
        return;
    }
    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) {
            char const *is_config_file = strstr(entry->d_name, config_file_suffix);
            if (is_config_file == NULL) continue;
            char rule_file[1024];
            snprintf(rule_file, sizeof(rule_file), "%s/%s", config_path, entry->d_name);
            int const ret = msc_rules_add_file(rules, rule_file, &rules_load_error);
            if (ret < 0) {
                fprintf(stderr, "Problems loading the rules --\n");
                fprintf(stderr, "%s\n", rules_load_error);
                kg_cleanup(rules_load_error, rules, modsec);
            }
            printf("loaded file: %s\n", (const char *) rule_file);
        }
    }
    closedir(dp);
}

void kg_library_init(char const *config_path) {
    // const char *error = NULL;
    modsec = msc_init();
    msc_set_connector_info(modsec, "KubeGuard v0.0.1-alpha");
    rules = msc_create_rules_set();
    load_rules_files(config_path);
    msc_rules_dump(rules);
}

void kg_cleanup(const char *error, RulesSet *rules, ModSecurity *modsec) {
    int res = 0;
    if (error != NULL) {
        msc_rules_error_cleanup(error);
        res = 1;
    }
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    exit(res);
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

void kg_init_request_transaction(EvaluationRequest *request) {
    // create new transaction
    request->transaction = msc_new_transaction(modsec, rules, NULL);
}

void kg_transaction_cleanup(EvaluationRequest const *request) {
    msc_transaction_cleanup(request->transaction);
}

int kg_process_request_body(EvaluationRequest const *request) {
    int intervention_status = 0;
    // process request body
    if (request->body != NULL) {
        // append request body
        msc_append_request_body(request->transaction,
                                (const unsigned char *) request->body,
                                strlen(request->body));
        // process request body
        msc_process_request_body(request->transaction);
        // check for intervention
        intervention_status = kg_process_intervention(request->transaction);
        if (intervention_status != 0) {
            return intervention_status;
        }
    }
    return intervention_status;
}

int kg_process_request_headers(EvaluationRequest const *request) {
    int intervention_status = 0;
    // process connection
    msc_process_connection(request->transaction, request->client_ip, 0, "0.0.0.0", 0);
    intervention_status = kg_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    // process URI and request headers
    msc_process_uri(request->transaction, request->uri, request->http_method, request->http_version);
    intervention_status = kg_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    for (size_t i = 0; i < request->headers_count; i++) {
        msc_add_request_header(request->transaction, request->headers[i].key, request->headers[i].value);
    }
    msc_process_request_headers(request->transaction);
    intervention_status = kg_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    return intervention_status;
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
