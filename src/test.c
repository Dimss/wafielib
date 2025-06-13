#include <stdio.h>
#include <kubeguardlib.h>

int main() {
    const char *file_path = "/example.conf";
    kg_library_init(file_path);
    // EvaluationRequestHeader headers[] = {
    //     {.key = (const unsigned char *) "Host", .value = (const unsigned char *) "example.com"},
    //     {.key = (const unsigned char *) "User-Agent", .value = (const unsigned char *) "KubeGuard/1.0"}
    // };

    EvaluationRequestHeader *headers1 = malloc(sizeof(EvaluationRequestHeader) * 2);
    // EvaluationRequestHeader *headers1;
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";


    EvaluationRequest const request = {
        .client_ip = "192.168.1.3",
        .uri = "/admin",
        .http_method = "GET",
        .http_version = "1.1",
        .headers_count = 2,
        .headers = headers1
    };
    kg_add_rule(
        "SecRule REMOTE_ADDR \"@ipMatch 192.168.1.2\" \"id:182374049403,phase:0,deny,status:403,msg:\'Blocking connection from specific IP\'\"");

    int const res = kg_evaluate(&request);
    free(headers1);
    fprintf(stdout, "evaluation result : %d\n", res);
}
