#include <stdio.h>
#include <kubeguardlib.h>

int main() {
    char const *config_path = "/config";
    kg_library_init(config_path);
    EvaluationRequestHeader *headers1 = malloc(sizeof(EvaluationRequestHeader) * 2);
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";


    EvaluationRequest request = {
        .client_ip = "192.168.1.3",
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

    fprintf(stdout, "headers evaluation result : %d\n", kg_process_request_headers(&request));
    fprintf(stdout, "body evaluation result : %d\n", kg_process_request_body(&request));
    free(headers1);
    kg_transaction_cleanup((EvaluationRequest * const) request.transaction);
}
