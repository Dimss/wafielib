#include "wafielib.h"
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <pthread.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"


ModSecurity *modsec;
WafieRuleSet *wrs[1000];
pthread_rwlock_t ruleset_lock = PTHREAD_RWLOCK_INITIALIZER;

ModSecurityIntervention wafie_new_intervention() {
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    intervention.pause = 0;
    return intervention;
}

// register logs call back
void wafie_log_cb(void *data, const void *msg) {
    fprintf(stderr, "%s\n", (const char *) msg);
}

static void wafie_load_main_configs(RulesSet *rule_set, char *config_path, int protection_id) {
    fprintf(stdout, "[libwafie.protection.id: %d] loading main configuration \n", protection_id);
    char **main_config_files = (char *[]){
        "modsecurity.conf",
        "crs-setup.conf",
    };
    const char *error = NULL;
    for (size_t i = 0; i < 2; i++) {
        char conf_file[strlen(main_config_files[i]) + strlen(config_path) + 2];
        snprintf(conf_file, sizeof(conf_file), "%s/%s", config_path, main_config_files[i]);
        // fprintf(stdout, "loading rule file: %s\n", conf_file);
        int const ret = msc_rules_add_file(rule_set, conf_file, &error);
        if (ret < 0) {
            fprintf(stderr, "problems loading the rules --\n");
            fprintf(stderr, "%s\n", error);
            if (error != NULL) {
                msc_rules_error_cleanup(error);
            }
        }
        // request->total_loaded_rules += ret;
    }
}

static void wafie_load_modescurity_rules_configs(RulesSet *rule_set, char *config_path, int protection_id) {
    fprintf(stdout, "[libwafie.protection.id: %d] loading rules \n", protection_id);
    const char *error = NULL;
    // const char *config_file_suffix = ".conf";
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
            // char const *is_config_file = strstr(entry->d_name, config_file_suffix);
            char const *is_config_file = strstr(entry->d_name, ".conf");
            if (is_config_file == NULL) continue;
            char rule_file[strlen(rules_path) + strlen(entry->d_name) + 2];
            snprintf(rule_file, sizeof(rule_file), "%s/%s", rules_path, entry->d_name);
            int const ret = msc_rules_add_file(rule_set, rule_file, &error);
            if (ret < 0) {
                fprintf(stderr, "problems loading the rules --\n");
                fprintf(stderr, "%s\n", error);
                if (error != NULL) {
                    msc_rules_error_cleanup(error);
                }
            }
            // printf("loading rule file: %s\n", (const char *) rule_file);
            // request->total_loaded_rules += ret;
        }
    }
    closedir(dp);
}

void wafie_init() {
    // init modesc
    modsec = msc_init();
    msc_set_log_cb(modsec, wafie_log_cb);
    msc_set_connector_info(modsec, "wafie v0.0.2-alpha");
}

void wafie_load_rule_sets(WafieRuleSetConfig cfg[], const int cfg_size) {
    // lock rules for RW
    pthread_rwlock_wrlock(&ruleset_lock);
    WafieRuleSet *wrs_swap[1000];
    for (int i = 0; i < cfg_size; i++) {
        wrs[i] = malloc(sizeof(WafieRuleSet));
        wrs[i]->protection_id = cfg[i].protection_id;
        wrs[i]->rules = msc_create_rules_set();
        // load main configurations files
        wafie_load_main_configs(wrs[i]->rules, cfg[i].config_path, wrs[i]->protection_id);
        // load the rules files
        wafie_load_modescurity_rules_configs(wrs[i]->rules, cfg[i].config_path, wrs[i]->protection_id);
    }
    // unlock rules for RW
    pthread_rwlock_unlock(&ruleset_lock);
}

// init transaction
void wafie_init_transaction(WafieEvaluationRequest *request) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    pthread_rwlock_rdlock(&ruleset_lock);
    fprintf(stdout, "[libwafie: protection id - %d] initializing evaluation request\n", request->protection_id);
    // init modesc
    // request->modsec = msc_init();
    // msc_set_log_cb(request->modsec, wafie_log_cb);
    // msc_set_connector_info(request->modsec, "wafie v0.0.2-alpha");
    // load rules
    // request->total_loaded_rules = 0;
    // request->rules = msc_create_rules_set();
    // wafie_load_modsecuirty_configuration(request);
    // init transaction
    int rule_set_idx = 0;
    for (int i = 0; i < 1; i++) {
        if (wrs[i]->protection_id == request->protection_id) {
            rule_set_idx = i;
            break;
        }
    }
    request->transaction = msc_new_transaction(modsec, wrs[rule_set_idx]->rules, NULL);
    pthread_rwlock_unlock(&ruleset_lock);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;
    fprintf(stdout, "[libwafie: protection id - %d] evaluation request initialization took  %.3f ms\n",
            request->protection_id, elapsed_ms);
}

// cleanup transaction
void wafie_cleanup(WafieEvaluationRequest const *request) {
    msc_process_logging(request->transaction);
    msc_transaction_cleanup(request->transaction);
}

// intervention flow
int wafie_process_intervention(Transaction *transaction) {
    ModSecurityIntervention intervention = wafie_new_intervention();
    if (msc_intervention(transaction, &intervention) == 0) {
        return 0;
    }
    if (intervention.log != NULL) {
        fprintf(stdout, "%s\n", intervention.log);
        free(intervention.log);
        intervention.log = NULL;
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

// process headers
int wafie_process_request_headers(WafieEvaluationRequest const *request) {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);
    fprintf(stdout, "[libwafie.protection.id: %d] processing request headers \n", request->protection_id);
    int intervention_status = 0;
    // process connection
    msc_process_connection(request->transaction, request->client_ip, 0, "0.0.0.0", 0);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    // process URI and request headers
    fprintf(stdout, "[libwafie.protection.id: %d] request uri -> %s\n", request->protection_id, request->uri);
    fprintf(stdout, "[libwafie.protection.id: %d] request method -> %s\n", request->protection_id,
            request->http_method);
    fprintf(stdout, "[libwafie.protection.id: %d] request version -> %s\n", request->protection_id,
            request->http_version);
    msc_process_uri(request->transaction, request->uri, request->http_method, request->http_version);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    for (size_t i = 0; i < request->headers_count; i++) {
        msc_add_request_header(request->transaction, request->headers[i].key, request->headers[i].value);
        fprintf(stdout, "[libwafie.protection.id: %d] request header -> %s: %s\n",
                request->protection_id,
                (const char *) request->headers[i].key,
                (const char *) request->headers[i].value);
    }
    msc_process_request_headers(request->transaction);
    intervention_status = wafie_process_intervention(request->transaction);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;
    fprintf(stdout, "[libwafie.protection.id: %d] processing request headers took  %.3f ms\n",
            request->protection_id, elapsed_ms);

    if (intervention_status != 0) {
        return intervention_status;
    }
    return intervention_status;
}

// process body
int wafie_process_request_body(WafieEvaluationRequest const *request) {
    struct timespec start, end;


    fprintf(stdout, "[libwafie.protection.id: %d] processing request body \n", request->protection_id);
    int intervention_status = 0;
    // process request body
    if (request->body != NULL) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        // append request body
        msc_append_request_body(request->transaction,
                                (const unsigned char *) request->body,
                                strlen(request->body));
        // process request body
        msc_process_request_body(request->transaction);
        // check for intervention
        intervention_status = wafie_process_intervention(request->transaction);
        clock_gettime(CLOCK_MONOTONIC, &end);

        long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
        double elapsed_ms = elapsed_ns / 1000000.0;
        fprintf(stdout, "[libwafie.protection.id: %d] processing request body took  %.3f ms\n",
                request->protection_id, elapsed_ms);

        if (intervention_status != 0) {
            return intervention_status;
        }
    }
    return intervention_status;
}
