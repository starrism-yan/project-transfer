// 修正后的完整代码（复制即可编译运行）
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>

#define PORT 4433
#define BUFFER_SIZE 8192
#define WEBROOT "./www"

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

SSL_CTX* create_ssl_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    if (!SSL_CTX_check_private_key(ctx)) { fprintf(stderr, "Private key mismatch\n"); exit(EXIT_FAILURE); }
    return ctx;
}

int create_listen_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); exit(EXIT_FAILURE); }
    if (listen(sock, 10) < 0) { perror("listen"); exit(EXIT_FAILURE); }
    return sock;
}

char* extract_get_path(const char* request) {
    char* req_copy = strdup(request);
    char* method = strtok(req_copy, " ");
    char* path = strtok(NULL, " ");
    if (!method || strcmp(method, "GET") != 0 || !path) { free(req_copy); return NULL; }
    char* result = strdup(path);
    free(req_copy);
    return result;
}

char* build_http_response(const char* path, int* out_len) {
    char full_path[512];
    if (strstr(path, "..") != NULL) {
        const char* forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        *out_len = strlen(forbidden);
        return strdup(forbidden);
    }
    if (strcmp(path, "/") == 0)
        snprintf(full_path, sizeof(full_path), "%s/index.html", WEBROOT);
    else
        snprintf(full_path, sizeof(full_path), "%s%s", WEBROOT, path);
    
    FILE* fp = fopen(full_path, "rb");
    if (!fp) {
        const char* not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>";
        *out_len = strlen(not_found);
        return strdup(not_found);
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* file_data = malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);
    const char* content_type = "text/plain";
    if (strstr(full_path, ".html")) content_type = "text/html";
    else if (strstr(full_path, ".css")) content_type = "text/css";
    char header[512];
    snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n", content_type, file_size);
    int header_len = strlen(header);
    char* response = malloc(header_len + file_size);
    memcpy(response, header, header_len);
    memcpy(response + header_len, file_data, file_size);
    free(file_data);
    *out_len = header_len + file_size;
    return response;
}

void* handle_connection(void* arg) {
    SSL* ssl = (SSL*)arg;
    char buffer[BUFFER_SIZE] = {0};
    int ret = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (ret <= 0) { ERR_print_errors_fp(stderr); SSL_shutdown(ssl); SSL_free(ssl); return NULL; }
    buffer[ret] = '\0';
    printf("Request:\n%s\n", buffer);
    char* path = extract_get_path(buffer);
    if (!path) {
        const char* bad = "HTTP/1.1 400 Bad Request\r\n\r\n";
        SSL_write(ssl, bad, strlen(bad));
    } else {
        int resp_len;
        char* response = build_http_response(path, &resp_len);
        SSL_write(ssl, response, resp_len);
        free(response);
        free(path);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return NULL;
}

int main() {
    init_openssl();
    SSL_CTX* ctx = create_ssl_ctx();
    int listen_sock = create_listen_socket(PORT);
    printf("HTTPS server running on https://localhost:%d\n", PORT);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &len);
        if (client_sock < 0) { perror("accept"); continue; }
        printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);
        if (SSL_accept(ssl) <= 0) { ERR_print_errors_fp(stderr); SSL_free(ssl); continue; }
        printf("TLS handshake done. Cipher: %s\n", SSL_get_cipher(ssl));
        pthread_t tid;
        pthread_create(&tid, NULL, handle_connection, (void*)ssl);
        pthread_detach(tid);
    }
    close(listen_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}