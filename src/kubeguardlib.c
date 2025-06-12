#include "kubeguardlib.h"

#include <stdio.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

ModSecurity *modsec;
RulesSet *rules;

void library_init(char const *file_path) {
    const char *error = NULL;
    modsec = msc_init();
    msc_set_connector_info(modsec, "KubeGuard v0.0.1-alpha");
    rules = msc_create_rules_set();
    int const ret = msc_rules_add_file(rules, file_path, &error);
    if (ret < 0) {
        fprintf(stderr, "Problems loading the rules --\n");
        fprintf(stderr, "%s\n", error);
        cleanup(error, rules, modsec);
    }
    msc_rules_dump(rules);
}

void cleanup(const char *error, RulesSet *rules, ModSecurity *modsec) {
    if (error != NULL) {
        msc_rules_error_cleanup(error);
    }
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    exit(1);
}

ModSecurityIntervention new_msc_intervention() {
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    intervention.pause = 0;
    return intervention;
}

int evaluate() {
    // const char *error = NULL;
    Transaction *transaction = msc_new_transaction(modsec, rules, NULL);
    msc_process_connection(transaction, "192.168.1.1", 12345, "127.0.0.1", 80);
    ModSecurityIntervention intervention = new_msc_intervention();
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
