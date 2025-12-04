#include <stdio.h>
#include <wafielib.h>
#include <stdlib.h>
#include <string.h>


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


int main() {
    EvaluationRequestHeader *headers1 = malloc(sizeof(EvaluationRequestHeader) * 2);
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";
    //
    //
    EvaluationRequest request = {
        .client_ip = "192.168.1.2",
        .uri = "/etc/passwd",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        .body = "",
        .config_path = "/config",
    };
    wafie_init(&request);
    wafie_process_request_headers(&request);
    wafie_process_request_body(&request);


    wafie_cleanup(&request);


    free(headers1);
    char *audit_content = read_file("/tmp/modsec_audit.log");
    if (audit_content) {
        printf("Config loaded: %zu bytes\n", strlen(audit_content));
        fprintf(stdout, "%s\n", audit_content);
        free(audit_content);
    }
}
