#ifndef KUBEGUARDLIB_LIBRARY_H
#define KUBEGUARDLIB_LIBRARY_H
#include <modsecurity/transaction.h>

void library_init(char const *file_path);

void dump_rules();

void cleanup(const char *error, RulesSet *rules, ModSecurity *modsec);

#endif //KUBEGUARDLIB_LIBRARY_H
