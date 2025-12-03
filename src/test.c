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
    wafie_library_init();
    EvaluationRequestHeader *headers1 = malloc(sizeof(EvaluationRequestHeader) * 2);
    headers1[0].key = (const unsigned char *) "Host";
    headers1[0].value = (const unsigned char *) "example.com";
    headers1[1].key = (const unsigned char *) "User-Agent";
    headers1[1].value = (const unsigned char *) "KubeGuard/1.0";
    //
    //
    int total_loaded_rules = 0;
    EvaluationRequest request = {
        .client_ip = "192.168.1.2",
        .uri = "/etc/passwd",
        .http_method = "GET",
        .http_version = "1.2",
        .headers_count = 2,
        .headers = headers1,
        // .body = NULL
        .body = "",
        .config_path = "/config",
        .total_loaded_rules = &total_loaded_rules,
    };


    // wafie_add_rule(
    //     "SecRule REMOTE_ADDR \"@ipMatch 192.168.1.2\" \"id:182374049403,phase:0,deny,status:403,msg:\'Blocking connection from specific IP\'\"");
    // wafie_add_rule("SecAction \"id:900000,phase:1,pass,t:none,nolog,tag:\'OWASP_CRS\',ver:\'OWASP_CRS/4.12.0\',setvar:tx.blocking_paranoia_level=4\"");
    // wafie_add_rule("SecAction \"id:203948180384,phase:1,log,pass,msg:'FOO-PARANOIA-LEVEL: %{tx.blocking_paranoia_level}'\"");
    // wafie_add_rule("SecAction \"id:900110,phase:1,nolog,pass,t:none,setvar:tx.anomaly_score_blocking=off\"");
    // wafie_add_rule("SecAction \"id:900120,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=0\"");
    // wafie_add_rule("SecAction \"id:900130,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=0\"");
    // wafie_add_rule("SecAction \"id:999999,phase:5,pass,log,msg:'Transaction complete'\"");
    wafie_init_request_transaction(&request);
    wafie_process_request_headers(&request);
    wafie_process_request_body(&request);
    // fprintf(stdout, "headers evaluation result : %d\n", wafie_process_request_headers(&request));
    // fprintf(stdout, "body evaluation result : %d\n", wafie_process_request_body(&request));

    wafie_transaction_cleanup(&request);


    free(headers1);
    char *audit_content = read_file("/tmp/modsec_audit.log");
    if (audit_content) {
        printf("Config loaded: %zu bytes\n", strlen(audit_content));
        fprintf(stdout, "%s\n", audit_content);
        free(audit_content);
    }
}
