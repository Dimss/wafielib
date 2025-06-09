#include "kubeguardlib.h"

#include <stdio.h>
#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"

void dump_rules(char const *file_path) {
    int ret;
    const char *error = NULL;
    ModSecurity *modsec;
    Transaction *transaction = NULL;
    RulesSet *rules;

    modsec = msc_init();
    msc_set_connector_info(modsec, "ModSecurity-test v0.0.1-alpha (Simple "
                           "example on how to use ModSecurity API");

    rules = msc_create_rules_set();
    ret = msc_rules_add_file(rules, file_path, &error);
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
