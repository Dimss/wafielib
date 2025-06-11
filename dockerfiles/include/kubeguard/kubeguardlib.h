#ifndef KUBEGUARDLIB_LIBRARY_H
#define KUBEGUARDLIB_LIBRARY_H
#include <modsecurity/transaction.h>

void dump_rules(char const *file_path);

void cleanup(const char *error, RulesSet *rules, ModSecurity *modsec);

#endif //KUBEGUARDLIB_LIBRARY_H
