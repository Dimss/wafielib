#include "wafielib.h"

#include <stdio.h>
#include <dirent.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

ModSecurity *modsec;
RulesSet *rules;

static void wafie_load_main_configs(char const *config_path, int *total_loaded_rules) {
    char **main_config_files = (char *[]){
        "modsecurity.conf",
        "crs-setup.conf",
    };
    const char *cfg_add_error = NULL;
    for (size_t i = 0; i < 2; i++) {
        char conf_file[strlen(main_config_files[i]) + strlen(config_path) + 2];
        snprintf(conf_file, sizeof(conf_file), "%s/%s", config_path, main_config_files[i]);
        // fprintf(stdout, "loading rule file: %s\n", conf_file);
        int const ret = msc_rules_add_file(rules, conf_file, &cfg_add_error);
        if (ret < 0) {
            fprintf(stderr, "problems loading the rules --\n");
            fprintf(stderr, "%s\n", cfg_add_error);
            wafie_cleanup(cfg_add_error, rules, modsec);
        }
        *total_loaded_rules += ret;
    }
    // wafie_add_rule("SecAction \"id:900000,phase:1,pass,t:none,nolog,tag:\'OWASP_CRS\',ver:\'OWASP_CRS/4.12.0\',setvar:tx.blocking_paranoia_level=1\"");
    //     wafie_add_rule("SecAction \"id:203948180384,phase:1,log,pass,msg:'FOO-PARANOIA-LEVEL: %{tx.blocking_paranoia_level}'\"");
    //     wafie_add_rule("SecAction \"id:900110,phase:1,nolog,pass,t:none,setvar:tx.anomaly_score_blocking=off\"");
    //     wafie_add_rule("SecAction \"id:900120,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=0\"");
    //     wafie_add_rule("SecAction \"id:900130,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=0\"");
}

static void wafie_load_modescurity_rules_configs(char const *config_path, int *total_loaded_rules) {
    const char *rules_load_error = NULL;
    const char *config_file_suffix = ".conf";
    // 7 = strlen("/rules") + 1
    char rules_path[strlen(config_path) + 7];
    snprintf(rules_path, sizeof(rules_path), "%s/rules", config_path);
    struct dirent *entry;
    DIR *dp = opendir(rules_path);
    if (dp == NULL) {
        perror("opendir");
        return;
    }
    // load the rules files
    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG) {
            char const *is_config_file = strstr(entry->d_name, config_file_suffix);
            if (is_config_file == NULL) continue;
            char rule_file[strlen(rules_path) + strlen(entry->d_name) + 2];
            snprintf(rule_file, sizeof(rule_file), "%s/%s", rules_path, entry->d_name);
            int const ret = msc_rules_add_file(rules, rule_file, &rules_load_error);
            if (ret < 0) {
                fprintf(stderr, "problems loading the rules --\n");
                fprintf(stderr, "%s\n", rules_load_error);
                wafie_cleanup(rules_load_error, rules, modsec);
            }
            // printf("loading rule file: %s\n", (const char *) rule_file);
            *total_loaded_rules += ret;
        }
    }
    closedir(dp);
}

static void wafie_load_modsecuirty_configuration(char const *config_path) {
    int total_loaded_rules = 0;
    // load main configurations files
    wafie_load_main_configs(config_path, &total_loaded_rules);
    // load the rules files
    wafie_load_modescurity_rules_configs(config_path, &total_loaded_rules);
    // print the total loaded rules
    fprintf(stdout, "[wafielib] total rules loaded: %d\n", total_loaded_rules);
}

void wafie_log_cb(void *data, const void *msg) {
    fprintf(stderr, "%s\n", (const char *) msg);
}

void wafie_library_init(char const *config_path) {
    modsec = msc_init();
    msc_set_log_cb(modsec, wafie_log_cb);
    msc_set_connector_info(modsec, "wafie v0.0.2-alpha");

    rules = msc_create_rules_set();
    wafie_load_modsecuirty_configuration(config_path);

    // msc_rules_dump(rules);
}

void wafie_cleanup(const char *error, RulesSet *rules, ModSecurity *modsec) {
    int res = 0;
    if (error != NULL) {
        msc_rules_error_cleanup(error);
        res = 1;
    }
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    exit(res);
}

ModSecurityIntervention wafie_new_intervention() {
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    intervention.pause = 0;
    return intervention;
}

int wafie_process_intervention(Transaction *transaction) {
    ModSecurityIntervention intervention = wafie_new_intervention();
    if (msc_intervention(transaction, &intervention) == 0) {
        return 0;
    }
    if (intervention.log != NULL) {
        fprintf(stdout, "%s\n", intervention.log);
        free(intervention.log);
    }
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
    if (intervention.disruptive != 0) {
        return intervention.disruptive;
    }
    return 0;
}

void wafie_init_request_transaction(EvaluationRequest *request) {
    // create new transaction
    request->transaction = msc_new_transaction(modsec, rules, NULL);
}

void wafie_transaction_cleanup(EvaluationRequest const *request) {
    msc_process_logging(request->transaction);
    msc_transaction_cleanup(request->transaction);
}

int wafie_process_request_body(EvaluationRequest const *request) {
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
        intervention_status = wafie_process_intervention(request->transaction);
        if (intervention_status != 0) {
            return intervention_status;
        }
    }
    return intervention_status;
}

int wafie_process_request_headers(EvaluationRequest const *request) {
    int intervention_status = 0;
    // process connection
    msc_process_connection(request->transaction, request->client_ip, 0, "0.0.0.0", 0);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    // process URI and request headers
    msc_process_uri(request->transaction, request->uri, request->http_method, request->http_version);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    for (size_t i = 0; i < request->headers_count; i++) {
        msc_add_request_header(request->transaction, request->headers[i].key, request->headers[i].value);
    }
    msc_process_request_headers(request->transaction);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    return intervention_status;
}

int wafie_add_rule(char const *rule) {
    const char *error = NULL;
    int const ret = msc_rules_add(rules, rule, &error);
    if (ret < 0) {
        fprintf(stderr, "problems adding the rule -- %s\n", rule);
        fprintf(stderr, "%s\n", error);
        return 1;
    }
    return 0;
}
