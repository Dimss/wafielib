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

int main(int argc, char *argv[]) {
    WafieRuleSetConfig cfg[2];
    cfg[0].protection_id = 1;
    cfg[0].config_path = "/tmp/newconfig";
    if (argc > 1) {
        printf("using config from: %s \n", argv[1]);
        cfg[0].config_path = argv[1];
    }


    //
    WafieEvaluationRequestHeader *headers = malloc(sizeof(WafieEvaluationRequestHeader) * 14);
    headers[0].key = (const unsigned char *) ":authority:";
    headers[0].value = (const unsigned char *) "wp.10.100.102.92.nip.io";
    headers[1].key = (const unsigned char *) ":path:";
    headers[1].value = (const unsigned char *) "/?id=1/**/UNION/**/SELECT/**/%27%3Cscript%3Ealert(1)%3C/script%3E%27";
    headers[2].key = (const unsigned char *) ":method:";
    headers[2].value = (const unsigned char *) "GET";
    headers[3].key = (const unsigned char *) ":scheme:";
    headers[3].value = (const unsigned char *) "http";
    headers[4].key = (const unsigned char *) "x-request-id";
    headers[4].value = (const unsigned char *) "2aa12cf48d6a515c00be63ced517d1e5";
    headers[5].key = (const unsigned char *) "x-real-ip";
    headers[5].value = (const unsigned char *) "10.244.0.1";
    headers[6].key = (const unsigned char *) "x-forwarded-for";
    headers[6].value = (const unsigned char *) "10.244.0.1";
    headers[7].key = (const unsigned char *) "x-forwarded-host";
    headers[7].value = (const unsigned char *) "wp.10.100.102.92.nip.io";
    headers[8].key = (const unsigned char *) "x-forwarded-port";
    headers[8].value = (const unsigned char *) "80";
    headers[9].key = (const unsigned char *) "x-forwarded-proto";
    headers[9].value = (const unsigned char *) "http";
    headers[10].key = (const unsigned char *) "x-forwarded-scheme";
    headers[10].value = (const unsigned char *) "http";
    headers[11].key = (const unsigned char *) "user-agent";
    headers[11].value = (const unsigned char *) "curl/8.7.1";
    headers[12].key = (const unsigned char *) "accept";
    headers[12].value = (const unsigned char *) " */*";
    headers[13].key = (const unsigned char *) "host";
    headers[13].value = (const unsigned char *) "wp.10.100.102.92.nip.io";

    // //
    WafieEvaluationRequest request1 = {
        .client_ip = "192.168.1.2",
        .uri = "/?id=1/**/UNION/**/SELECT/**/%27%3Cscript%3Ealert(1)%3C/script%3E%27",
        .http_method = "GET",
        .http_version = "1.1",
        .headers_count = 2,
        .headers = headers,
        .protection_id = 1,
    };

    wafie_init();
    wafie_load_rule_sets(cfg, 1);
    wafie_init_transaction(&request1);
    wafie_process_request_headers(&request1);
    // wafie_process_request_body(&request1);
    wafie_cleanup(&request1);



    free(headers);

    char *audit_content = read_file("/tmp/modsec_audit.log");
    if (audit_content) {
        printf("Config loaded: %zu bytes\n", strlen(audit_content));
        fprintf(stdout, "%s\n", audit_content);
        free(audit_content);
    }
}
