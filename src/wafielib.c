#include "wafielib.h"
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/time.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

#ifndef WAFIE_RULESET_BUFFER_SIZE
#define WAFIE_RULESET_BUFFER_SIZE 1000
#endif


ModSecurity *modsec;
WafieRuleSet *wrs[WAFIE_RULESET_BUFFER_SIZE];
WafieRuleSet *wrs_swap[WAFIE_RULESET_BUFFER_SIZE];
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

static void wafie_load_main_configs(RulesSet *rule_set, char *config_path, uint32_t protection_id) {
    fprintf(stdout, "[libwafie.wafie_load_main_configs.protection.id: %d] path %s loading main configuration \n",
            protection_id, config_path);
    char **main_config_files = (char *[]){
        "modsecurity.conf",
        "crs-setup.conf",
    };
    const char *error = NULL;
    for (size_t i = 0; i < 2; i++) {
        char conf_file[strlen(main_config_files[i]) + strlen(config_path) + 2];
        snprintf(conf_file, sizeof(conf_file), "%s/%s", config_path, main_config_files[i]);
        fprintf(stdout, "[libwafie.wafie_load_main_configs.protection.id: %d] loading rule file: %s\n",
                protection_id, conf_file);
        int const ret = msc_rules_add_file(rule_set, conf_file, &error);
        if (ret < 0) {
            fprintf(stderr, "[libwafie.wafie_load_main_configs.protection.id: %d] problems loading the rules \n",
                    protection_id);
            fprintf(stderr, "%s\n", error);
            if (error != NULL) {
                msc_rules_error_cleanup(error);
            }
        }
    }
}

static void wafie_load_modescurity_rules_configs(RulesSet *rule_set, char *config_path, uint32_t protection_id) {
    fprintf(stdout, "[libwafie.wafie_load_modescurity_rules_configs.protection.id: %d] loading rules \n",
            protection_id);
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
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    fprintf(stdout, "[libwafie.wafie_load_rule_sets] reloading ruleset \n");
    for (int i = 0; i < cfg_size; i++) {
        wrs_swap[i] = malloc(sizeof(WafieRuleSet));
        wrs_swap[i]->protection_id = cfg[i].protection_id;
        wrs_swap[i]->rules = msc_create_rules_set();
        // load main configurations files
        wafie_load_main_configs(wrs_swap[i]->rules, cfg[i].config_path, wrs_swap[i]->protection_id);
        // load the rules files
        wafie_load_modescurity_rules_configs(wrs_swap[i]->rules, cfg[i].config_path, wrs_swap[i]->protection_id);
    }
    // lock rules for RW
    pthread_rwlock_wrlock(&ruleset_lock);
    WafieRuleSet *old_rules[WAFIE_RULESET_BUFFER_SIZE];
    for (int i = 0; i < WAFIE_RULESET_BUFFER_SIZE; i++) {
        old_rules[i] = wrs[i]; // Save old pointers
        wrs[i] = (i < cfg_size) ? wrs_swap[i] : NULL; // Atomic pointer swap
        wrs_swap[i] = NULL;
    }
    // unlock rules for RW
    pthread_rwlock_unlock(&ruleset_lock);
    // Clean up old rules after lock is released
    for (int i = 0; i < WAFIE_RULESET_BUFFER_SIZE; i++) {
        if (old_rules[i] != NULL) {
            msc_rules_cleanup(old_rules[i]->rules);
            free(old_rules[i]);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;
    fprintf(stdout, "[libwafie.wafie_load_rule_sets] reload ruleset took  %.3f ms\n", elapsed_ms);
}

// init transaction
void wafie_init_transaction(WafieEvaluationRequest *request) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    // read lock
    pthread_rwlock_rdlock(&ruleset_lock);
    fprintf(stdout, "[libwafie.wafie_init_transaction.protection id - %d] initializing evaluation request\n",
            request->protection_id);
    // init transaction
    int rule_set_idx = -1;
    for (int i = 0; i < WAFIE_RULESET_BUFFER_SIZE; i++) {
        if (wrs[i] != NULL && wrs[i]->protection_id == request->protection_id) {
            rule_set_idx = i;
            break;
        }
    }
    if (rule_set_idx == -1) {
        fprintf(
            stderr, "[libwafie.wafie_init_transaction.protection id - %d] error: no ruleset found for protection_id\n",
            request->protection_id);
    } else {
        request->transaction = msc_new_transaction(modsec, wrs[rule_set_idx]->rules, NULL);
    }
    // read unlock
    pthread_rwlock_unlock(&ruleset_lock);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;
    fprintf(
        stdout,
        "[libwafie.wafie_init_transaction.protection id - %d] evaluation request initialization took  %.3f ms\n",
        request->protection_id, elapsed_ms);
}

// cleanup transaction
void wafie_cleanup(WafieEvaluationRequest const *request) {
    if (request->transaction == NULL) return;
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
    if (request->transaction == NULL) {
        fprintf(stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] transaction is NULL, skipping \n",
                request->protection_id);
        return 0;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    fprintf(stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] processing request \n",
            request->protection_id);
    int intervention_status = 0;
    // process connection
    msc_process_connection(request->transaction, request->client_ip, 0, "0.0.0.0", 0);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        return intervention_status;
    }
    // process URI and request headers
    fprintf(stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] uri -> %s\n",
            request->protection_id, request->uri);
    fprintf(stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] method -> %s\n",
            request->protection_id,
            request->http_method);
    fprintf(stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] version -> %s\n",
            request->protection_id,
            request->http_version);
    msc_process_uri(request->transaction, request->uri, request->http_method, request->http_version);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        goto finish_processing;
    }
    for (size_t i = 0; i < request->headers_count; i++) {
        msc_add_request_header(request->transaction, request->headers[i].key, request->headers[i].value);
        fprintf(stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] header -> %s: %s\n",
                request->protection_id,
                (const char *) request->headers[i].key,
                (const char *) request->headers[i].value);
    }
    // process headers phase
    msc_process_request_headers(request->transaction);
    intervention_status = wafie_process_intervention(request->transaction);
    if (intervention_status != 0) {
        goto finish_processing;
    }
    // process body phase
    msc_process_request_body(request->transaction);
    intervention_status = wafie_process_intervention(request->transaction);
    // unconditionally finish processing once intervention detected
finish_processing:
    clock_gettime(CLOCK_MONOTONIC, &end);
    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;
    fprintf(
        stdout, "[libwafie.wafie_process_request_headers.protection.id: %d] processing request took  %.3f ms\n",
        request->protection_id, elapsed_ms);

    if (intervention_status != 0) {
        return intervention_status;
    }
    return intervention_status;
}

// process body
int wafie_process_request_body(WafieEvaluationRequest const *request) {
    if (request->transaction == NULL) {
        fprintf(stdout, "[libwafie.wafie_process_request_body.protection.id: %d] transaction is NULL, skipping \n",
                request->protection_id);
        return 0;
    }
    struct timespec start, end;
    fprintf(stdout, "[libwafie.wafie_process_request_body.protection.id: %d] processing request\n",
            request->protection_id);
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
        fprintf(stdout, "[libwafie.wafie_process_request_body.protection.id: %d] processing request took  %.3f ms\n",
                request->protection_id, elapsed_ms);

        if (intervention_status != 0) {
            return intervention_status;
        }
    }
    return intervention_status;
}
