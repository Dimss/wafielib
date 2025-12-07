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
    WafieRuleSetConfig cfg[3];
    cfg[0].protection_id = 1;
    cfg[0].config_path = "/config1";
    cfg[1].protection_id = 2;
    cfg[1].config_path = "/config2";
    cfg[2].protection_id = 3;
    cfg[2].config_path = "/config3";
    wafie_load_rule_sets(cfg, 3);
    return NULL;
}

int main() {
    // WafieRuleSetConfig *cfg = malloc(sizeof(WafieRuleSetConfig) * 2);
    WafieRuleSetConfig cfg[2];
    cfg[0].protection_id = 1;
    cfg[0].config_path = "/config1";
    cfg[1].protection_id = 2;
    cfg[1].config_path = "/config2";


    WafieEvaluationRequestHeader *headers1 = malloc(sizeof(WafieEvaluationRequestHeader) * 2);
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";
    //
    //
    WafieEvaluationRequest request1 = {
        .client_ip = "192.168.1.2",
        .uri = "/etc/passwd",
        .http_method = "GET",
        .http_version = "1.1",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .protection_id = 1,
    };
    WafieEvaluationRequest request2 = {
        .client_ip = "192.168.1.3",
        .uri = "/foo/bar",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .protection_id = 2,
    };
    WafieEvaluationRequest request3 = {
        .client_ip = "192.168.1.3",
        .uri = "/foo/bar",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .protection_id = 3,
    };
    WafieEvaluationRequest request4 = {
        .client_ip = "192.168.1.3",
        .uri = "/foo/bar",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .protection_id = 3,
    };
    WafieEvaluationRequest request5 = {
        .client_ip = "192.168.1.3",
        .uri = "/foo/bar",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .protection_id = 3,
    };
    WafieEvaluationRequest request6 = {
        .client_ip = "192.168.1.3",
        .uri = "/foo/bar",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .protection_id = 2,
    };


    wafie_init();
    wafie_load_rule_sets(cfg, 2);

    pthread_t thread1;
    pthread_t thread2;
    pthread_t thread3;
    pthread_t thread4;
    pthread_t thread5;
    pthread_t thread6;
    pthread_t thread_reload_ruleset;

    const int t1 = pthread_create(&thread1, NULL, evalu_request, &request1);
    const int t2 = pthread_create(&thread2, NULL, evalu_request, &request2);
    const int th7 = pthread_create(&thread_reload_ruleset, NULL, reload_ruleset, NULL);
    const int t3 = pthread_create(&thread3, NULL, evalu_request, &request3);
    const int t4 = pthread_create(&thread4, NULL, evalu_request, &request4);
    const int t5 = pthread_create(&thread5, NULL, evalu_request, &request5);
    const int t6 = pthread_create(&thread6, NULL, evalu_request, &request6);
    if (t1 || t2 || t3 || t4 || t5 || t6 || th7) {
        fprintf(stderr, "Error - pthread_create() return code: %d\n", t1 || t2);
        exit(EXIT_FAILURE);
    }

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    pthread_join(thread4, NULL);
    pthread_join(thread5, NULL);
    pthread_join(thread6, NULL);
    pthread_join(thread_reload_ruleset, NULL);

    free(headers1);

    char *audit_content = read_file("/tmp/modsec_audit.log");
    if (audit_content) {
        printf("Config loaded: %zu bytes\n", strlen(audit_content));
        fprintf(stdout, "%s\n", audit_content);
        free(audit_content);
    }
}
