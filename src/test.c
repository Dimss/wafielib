#include <stdio.h>
#include <kubeguardlib.h>

int main() {
    const char *file_path = "/example.conf";
    library_init(file_path);
    int const res = evaluate();
    fprintf(stdout, "evaluation result : %d\n", res);
}
