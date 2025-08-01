#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include "auth_user.h"

#define EXE_PORT 9998
#define PORT 5433
#define MAX_PARAM_LEN 256
#define INITIAL_CACHE_SIZE 5

typedef struct {
    char user[MAX_PARAM_LEN];
    char database[MAX_PARAM_LEN];
    char password[MAX_PARAM_LEN];
} StartupParams;

typedef struct {
    char username[MAX_PARAM_LEN];
    char password[MAX_PARAM_LEN];
    char database[MAX_PARAM_LEN];
} Cache;

volatile sig_atomic_t stop_server = 0;

void handle_sigint(int sig) {
    stop_server = 1;
}

int read_n_bytes(int sock, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(sock, (char *)buf + total, n - total);
        if (r <= 0) return -1;
        total += r;
    }
    return 0;
}

void send_auth_request_cleartext(int client_fd) {
    char msg[] = { 'R', 0, 0, 0, 8, 0, 0, 0, 3 };
    write(client_fd, msg, sizeof(msg));
}

int receive_password(int client_fd, char *password_buf, size_t bufsize) {
    char type;
    uint32_t len_net;
    if (read_n_bytes(client_fd, &type, 1) != 0 || type != 'p'){
      return -1;
    } 
    if (read_n_bytes(client_fd, &len_net, 4) != 0){
      return -1;
    } 
    uint32_t len = ntohl(len_net);
    if (len <= 4 || len > bufsize){
      return -1;
    } 
    if (read_n_bytes(client_fd, password_buf, len - 4) != 0){
       return -1;
    }
    password_buf[len - 5] = '\0';
    return 0;
}

int handle_startup_message(int client_fd, StartupParams *params) {
    uint32_t len_net;
    if (read_n_bytes(client_fd, &len_net, 4) != 0){
       return -1;
    }
    uint32_t len = ntohl(len_net);
    if (len < 8 || len > 8192) {
      return -1;
    }

    char *buffer = malloc(len - 4);
    if (!buffer) return -1;
    if (read_n_bytes(client_fd, buffer, len - 4) != 0) {
        free(buffer);
        return -1;
    }

    uint32_t protocol = ntohl(*(uint32_t *)buffer);
    if (protocol != 0x00030000) {
        free(buffer);
        return -1;
    }

    memset(params, 0, sizeof(StartupParams));
    char *ptr = buffer + 4;
    char *end = buffer + len - 4;

    while (ptr < end && *ptr != '\0') {
        char *key = ptr;
        ptr += strlen(key) + 1;
        if (ptr >= end){
          break;
        } 
        char *val = ptr;
        ptr += strlen(val) + 1;
        if (strcmp(key, "user") == 0){
           strncpy(params->user, val, MAX_PARAM_LEN - 1);
        }
        else if (strcmp(key, "database") == 0){
          strncpy(params->database, val, MAX_PARAM_LEN - 1);
        } 
    }

    free(buffer);
    return 0;
}

void send_auth_ok(int client_fd) {
    char ok[] = { 'R', 0, 0, 0, 8, 0, 0, 0, 0 };
    write(client_fd, ok, sizeof(ok));

    const char *key = "client_encoding", *val = "UTF8";
    uint32_t len = 4 + strlen(key) + 1 + strlen(val) + 1;
    char *msg = malloc(1 + len);
    msg[0] = 'S';
    *(uint32_t *)(msg + 1) = htonl(len);
    strcpy(msg + 5, key);
    strcpy(msg + 5 + strlen(key) + 1, val);
    write(client_fd, msg, 1 + len);
    free(msg);

    char backend_key[] = {
        'K', 0, 0, 0, 12, 0, 0, 4, 210, 0, 0, 0, 42
    };
    write(client_fd, backend_key, sizeof(backend_key));

    char ready[] = { 'Z', 0, 0, 0, 5, 'I' };
    write(client_fd, ready, sizeof(ready));
}

void send_error_and_close(int client_fd, const char *message) {
    const char *severity = "ERROR";
    const char *code = "28000";
    size_t len = 1 + strlen(severity) + 1 + 1 + strlen(code) + 1 +
                 1 + strlen(message) + 1 + 1;
    uint32_t msglen = (uint32_t)(len + 4);
    char *buf = malloc(1 + msglen);
    if (!buf) return;
    buf[0] = 'E';
    *(uint32_t *)(buf + 1) = htonl(msglen);
    size_t offset = 5;
    buf[offset++] = 'S';
    strcpy(buf + offset, severity);
    offset += strlen(severity) + 1;
    buf[offset++] = 'C';
    strcpy(buf + offset, code);
    offset += strlen(code) + 1;
    buf[offset++] = 'M';
    strcpy(buf + offset, message);
    offset += strlen(message) + 1;
    buf[offset++] = '\0';
    write(client_fd, buf, offset);
    free(buf);
    close(client_fd);
}

void send_result(int client_fd, const char* command, const char *msg) {
    const char *colname = "result";
    uint32_t msglen = strlen(msg);
    uint32_t len = 4 + 2 + strlen(colname) + 1 + 4 + 2 + 4 + 2 + 4 + 2;

    char *rowdesc = malloc(1 + len);
    rowdesc[0] = 'T';
    *(uint32_t *)(rowdesc + 1) = htonl(len);
    *(uint16_t *)(rowdesc + 5) = htons(1);
    size_t offset = 7;
    strcpy(rowdesc + offset, colname);
    offset += strlen(colname) + 1;
    *(uint32_t *)(rowdesc + offset) = htonl(0); 
    offset += 4;
    *(uint16_t *)(rowdesc + offset) = htons(0);
    offset += 2;
    *(uint32_t *)(rowdesc + offset) = htonl(25);
    offset += 4;
    *(uint16_t *)(rowdesc + offset) = htons(-1);
    offset += 2;
    *(uint32_t *)(rowdesc + offset) = htonl(0);
    offset += 4;
    *(uint16_t *)(rowdesc + offset) = htons(0);
    write(client_fd, rowdesc, 1 + len);
    free(rowdesc);

    uint32_t dr_len = 4 + 2 + 4 + msglen;
    char *data_row = malloc(1 + dr_len);
    data_row[0] = 'D';
    *(uint32_t *)(data_row + 1) = htonl(dr_len);
    *(uint16_t *)(data_row + 5) = htons(1);
    *(uint32_t *)(data_row + 7) = htonl(msglen);
    memcpy(data_row + 11, msg, msglen);
    write(client_fd, data_row, 1 + dr_len);
    free(data_row);

    uint32_t cc_len = 4 + strlen(command) + 1;
    char *cc = malloc(1 + cc_len);
    cc[0] = 'C';
    *(uint32_t *)(cc + 1) = htonl(cc_len);
    memcpy(cc + 5, command, strlen(command) + 1);
    write(client_fd, cc, 1 + cc_len);
    free(cc);

    char ready[] = { 'Z', 0, 0, 0, 5, 'I' };
    write(client_fd, ready, sizeof(ready));
}

void send_to_executor(char* sql_query, char* database, char * exe_buffer) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(EXE_PORT)
    };
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Executor connection failed");
        close(server_socket);
        return;
    }
    int dlen = strlen(database);
    write(server_socket, &dlen, 4);
    write(server_socket, database, dlen);
    write(server_socket, sql_query, strlen(sql_query));
    read(server_socket, exe_buffer, 9000);
    close(server_socket);
}

int find_in_cache(int size, Cache* kash, StartupParams params) {
    for (int i = 0; i < size; i++) {
        if (strcmp(kash[i].username, params.user) == 0 &&
            strcmp(kash[i].database, params.database) == 0 &&
            strcmp(kash[i].password, params.password) == 0) {
            return 0;
        }
    }
    return 1;
}

void handle_client(int cfd, Cache **kash_ptr, int *cache_size_ptr) {
    StartupParams params = {0};
    char pw[MAX_PARAM_LEN] = {0};
    char exe_buffer[9000] = {0};
    char *sql_query = NULL;

    if (handle_startup_message(cfd, &params) != 0) {
        send_error_and_close(cfd, "Invalid startup message");
        return;
    }

    send_auth_request_cleartext(cfd);
    if (receive_password(cfd, pw, sizeof(pw)) != 0) {
        send_error_and_close(cfd, "Password read error");
        return;
    }
    strncpy(params.password, pw, MAX_PARAM_LEN - 1);

    if (find_in_cache(*cache_size_ptr, *kash_ptr, params) == 0) {
        send_auth_ok(cfd);
    } else {
        if (auth_req(params.user, params.password) != 0) {
            send_error_and_close(cfd, "Authentication failed");
            return;
        }
        (*cache_size_ptr)++;
        *kash_ptr = realloc(*kash_ptr, sizeof(Cache) * (*cache_size_ptr));
        if (!*kash_ptr) {
            send_error_and_close(cfd, "Cache realloc failed");
            return;
        }
        Cache *new_entry = &(*kash_ptr)[*cache_size_ptr - 1];
        strcpy(new_entry->username, params.user);
        strcpy(new_entry->password, params.password);
        strcpy(new_entry->database, params.database);
        send_auth_ok(cfd);
    }

    char msg_type;
    uint32_t msg_len_net;

    if (read_n_bytes(cfd, &msg_type, 1) != 0 || msg_type != 'Q') {
        send_error_and_close(cfd, "Expected query message");
        return;
    }

    if (read_n_bytes(cfd, &msg_len_net, 4) != 0) {
        send_error_and_close(cfd, "Message length error");
        return;
    }

    uint32_t msg_len = ntohl(msg_len_net);
    sql_query = malloc(msg_len - 4);
    if (!sql_query || read_n_bytes(cfd, sql_query, msg_len - 4) != 0) {
        send_error_and_close(cfd, "Query read failed");
        free(sql_query);
        return;
    }

    send_to_executor(sql_query, params.database, exe_buffer);
    send_result(cfd, sql_query, exe_buffer);
    free(sql_query);
}

int main() {
    signal(SIGINT, handle_sigint);

    int cache_size = INITIAL_CACHE_SIZE;
    Cache* kash = malloc(sizeof(Cache) * cache_size);
    if (!kash) {
        perror("Failed to allocate cache");
        return 1;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 5);

    printf("Server listening on port %d\n", PORT);
    while (!stop_server) {
        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) continue;
        handle_client(cfd, &kash, &cache_size);
        close(cfd);
    }

    close(s);
    free(kash);
    printf("Server shut down.\n");
    return 0;
}
