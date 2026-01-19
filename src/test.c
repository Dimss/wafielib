#include <stdio.h>
#include <wafielib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>


char *read_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    char *content = malloc(size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }

    // Read file
    fread(content, 1, size, file);
    content[size] = '\0';

    fclose(file);
    return content;
}

void *evalu_request(void *ptr) {
    WafieEvaluationRequest *request = ptr;
    for (int i = 0; i < 3; i++) {
        wafie_init_transaction(request);
        if (request->transaction != NULL) {
            wafie_process_request_headers(request);
            wafie_process_request_body(request);
            wafie_cleanup(request);
            break;
        }
        sleep(1);
    }

    return NULL;
}

void *reload_ruleset(void *ptr) {
    WafieRuleSetConfig cfg[1];
    cfg[0].protection_id = 1;
    cfg[0].config_path = "/tmp/empty-config";

    wafie_load_rule_sets(cfg, 3);
    return NULL;
}

int main() {
    // WafieRuleSetConfig *cfg = malloc(sizeof(WafieRuleSetConfig) * 2);
    WafieRuleSetConfig cfg[1];
    cfg[0].protection_id = 1;
    cfg[0].config_path = "/tmp/empty-config";
    // cfg[1].protection_id = 2;
    // cfg[1].config_path = "/config2";


    WafieEvaluationRequestHeader *headers1 = malloc(sizeof(WafieEvaluationRequestHeader) * 3);
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";
    headers1[2].key = (const unsigned char *) "Content-Type";
    headers1[2].value = (const unsigned char *) "application/x-www-form-urlencoded";

    WafieEvaluationRequestHeader *headers2 = malloc(sizeof(WafieEvaluationRequestHeader) * 3);
    headers2[0].key = (const unsigned char *) "Host";
    headers2[0].value = (const unsigned char *) "example.com";
    headers2[1].key = (const unsigned char *) "User-Agent";
    headers2[1].value = (const unsigned char *) "KubeGuard/1.0";
    headers2[2].key = (const unsigned char *) "Content-Type";
    headers2[2].value = (const unsigned char *) "application/x-www-form-urlencoded";
    // headers1[3].key = (const unsigned char *) "Content-Length";
    // headers1[3].value = (const unsigned char *) "7"; // strlen("foo=bar")

    WafieEvaluationRequest request1 = {
        .client_ip = "192.168.127.1",
        .uri = "/v2/g-recaptcha-response",
        .http_method = "POST",
        .http_version = "1.1",
        .request_headers_count = 3,
        .request_headers = headers1,
        .response_headers_count = 3,
        .response_headers = headers2,
        .response_code = 200,
        .protocol = "HTTP/1.1",
        // .body = "foo=bar",
        .protection_id = 1,
    };
    //
    //


    wafie_init();
    wafie_load_rule_sets(cfg, 1);
    wafie_init_transaction(&request1);
    //request
    wafie_process_request_headers(&request1);
    request1.request_body = "foo=bar";
    wafie_process_request_body(&request1);
    // response
    wafie_process_response_headers(&request1);
    // request1.response_body = "{foo:bar}";
    wafie_process_response_body(&request1);
    //cleanup
    wafie_cleanup(&request1);


    free(headers1);


    char *audit_content = read_file("/tmp/modsec_audit.log");
    if (audit_content) {
        printf("Config loaded: %zu bytes\n", strlen(audit_content));
        fprintf(stdout, "%s\n", audit_content);
        free(audit_content);
    }
}
