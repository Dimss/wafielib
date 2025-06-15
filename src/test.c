#include <stdio.h>
#include <kubeguardlib.h>

int main() {
    const char *file_path = "/example.conf";
    kg_library_init(file_path);
    // EvaluationRequestHeader headers[] = {
    //     {.key = (const unsigned char *) "Host", .value = (const unsigned char *) "example.com"},
    //     {.key = (const unsigned char *) "User-Agent", .value = (const unsigned char *) "KubeGuard/1.0"}
    // };
    const unsigned char *key1 = (const unsigned char *) "Host";
    const unsigned char *key2 = (const unsigned char *) "User-Agent";
    EvaluationRequestHeader *headers1 = malloc(sizeof(EvaluationRequestHeader) * 2);
    // EvaluationRequestHeader *headers1;
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";


    EvaluationRequest request = {
        .client_ip = "192.168.1.2",
        .uri = "/",
        .http_method = "GET",
        .http_version = "1.1",
        .headers_count = 2,
        .headers = headers1,
        // .body = NULL
        .body = "<html><body>Test</body></html>",
    };
    kg_init_request_transaction(&request);
    kg_add_rule(
        "SecRule REMOTE_ADDR \"@ipMatch 192.168.1.2\" \"id:182374049403,phase:0,deny,status:403,msg:\'Blocking connection from specific IP\'\"");

    int const res = kg_process_request_headers(&request);
    free(headers1);
    fprintf(stdout, "evaluation result : %d\n", res);
}
