#include <stdio.h>
#include <kubeguardlib.h>

int main() {
    const char *file_path = "/example.conf";
    library_init(file_path);
    EvaluationRequest const request = {
        .client_ip = "192.168.1.1"
    };
    int const res = evaluate(&request);
    fprintf(stdout, "evaluation result : %d\n", res);
}
