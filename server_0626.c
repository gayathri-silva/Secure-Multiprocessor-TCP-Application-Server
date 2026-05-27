#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <crypt.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#define PORT 50626
#define SID "1006"
#define BASE_DIR "/srv/ie2102/IT24100626/"
#define MAX_PAYLOAD 4096
#define LOG_FILE "server_IT24100626.log"

FILE *log_fp;

void log_event(const char *client_ip, int client_port, pid_t pid, const char *username, const char *command, const char *result) {
    time_t now = time(NULL);
    char time_str[26];
    ctime_r(&now, time_str);
    time_str[strlen(time_str)-1] = '\0';
    fprintf(log_fp, "%s | %s:%d | %d | %s | %s | %s\n", 
            time_str, client_ip, client_port, pid, username ? username : "-", command, result);
    fflush(log_fp);
}

void sigchld_handler(int s) {
    (void)s;  // suppress unused parameter warning
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int create_dir(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        return mkdir(path, 0755);
    }
    return 0;
}

char *generate_salt() {
    static char salt[20];
    srand(time(NULL));
    strcpy(salt, "$6$");
    for (int i = 3; i < 11; i++) {
        salt[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"[rand() % 64];
    }
    salt[11] = '$';
    salt[12] = '\0';
    return salt;
}

char *get_user_dir(const char *user) {
    static char path[512];
    snprintf(path, sizeof(path), "%s%s/", BASE_DIR, user);
    return path;
}

char *get_user_hash(const char *user) {
    char path[512];
    snprintf(path, sizeof(path), "%scredentials.txt", get_user_dir(user));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    static char hash[512];
    if (fgets(hash, sizeof(hash), f)) {
        hash[strcspn(hash, "\n")] = '\0';
        fclose(f);
        return hash;
    }
    fclose(f);
    return NULL;
}

int save_user_hash(const char *user, const char *hash) {
    char path[512];
    snprintf(path, sizeof(path), "%scredentials.txt", get_user_dir(user));
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", hash);
    fclose(f);
    return 0;
}

int validate_username(const char *user) {
    if (strlen(user) < 4 || strlen(user) > 20) return 0;
    for (int i = 0; user[i]; i++) {
        if (!isalnum(user[i])) return 0;
    }
    return 1;
}

int main() {
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) { 
        perror("Cannot open log file"); 
        exit(1); 
    }
    create_dir(BASE_DIR);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        exit(1);
    }

    signal(SIGCHLD, sigchld_handler);

    printf(" Server running on port %d | SID:%s\n", PORT, SID);
    printf("   Ready for clients...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {  // CHILD PROCESS
            close(server_fd);

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            int client_port = ntohs(client_addr.sin_port);
            pid_t child_pid = getpid();

            char *username = NULL;
            char session_token[64] = "";
            time_t last_activity = time(NULL);
            int failed_logins = 0;
            int cmd_count = 0;

            char recv_buf[8192];
            int buf_len = 0;

            while (1) {
                int bytes = recv(client_fd, recv_buf + buf_len, sizeof(recv_buf) - buf_len - 1, 0);
                if (bytes <= 0) break;
                buf_len += bytes;
                recv_buf[buf_len] = '\0';

                if (buf_len < 4 || strncmp(recv_buf, "LEN:", 4) != 0) {
                    char err[512];
                    snprintf(err, sizeof(err), "ERR 400 SID:%s Invalid framing", SID);
                    send(client_fd, err, strlen(err), 0);
                    break;
                }

                char *space = strchr(recv_buf + 4, ' ');
                if (!space) continue;

                char num_str[20] = {0};
                strncpy(num_str, recv_buf + 4, space - (recv_buf + 4));
                int n = atoi(num_str);

                if (n <= 0 || n > MAX_PAYLOAD) {
                    char err[512];
                    snprintf(err, sizeof(err), "ERR 413 SID:%s Invalid/oversized payload", SID);
                    send(client_fd, err, strlen(err), 0);
                    log_event(client_ip, client_port, child_pid, username, "OVERSIZE", "ERR 413");
                    break;
                }

                char *payload_start = space + 1;
                int header_len = payload_start - recv_buf;
                if (buf_len < header_len + n) continue;

                char payload[MAX_PAYLOAD + 1];
                strncpy(payload, payload_start, n);
                payload[n] = '\0';

                int consumed = header_len + n;
                memmove(recv_buf, recv_buf + consumed, buf_len - consumed);
                buf_len -= consumed;

                if (time(NULL) - last_activity > 300) {
                    strcpy(session_token, "");
                    if (username) free(username);
                    username = NULL;
                }
                last_activity = time(NULL);

                if (++cmd_count > 20) {
                    char err[512];
                    snprintf(err, sizeof(err), "ERR 429 SID:%s Rate limit exceeded", SID);
                    send(client_fd, err, strlen(err), 0);
                    continue;
                }

                char *words[10];
                int word_count = 0;
                char *p = strtok(payload, " ");
                while (p && word_count < 10) {
                    words[word_count++] = p;
                    p = strtok(NULL, " ");
                }
                if (word_count == 0) continue;

                char *cmd = words[0];
                int is_protected = (strcmp(cmd, "REGISTER") != 0 && strcmp(cmd, "LOGIN") != 0);

                char response[1024];

                if (strcmp(cmd, "REGISTER") == 0) {
                    if (word_count < 3 || !validate_username(words[1])) {
                        snprintf(response, sizeof(response), "ERR 400 SID:%s Invalid username or usage", SID);
                    } else {
                        char *user = words[1];
                        char *pass = words[2];
                        create_dir(get_user_dir(user));

                        if (get_user_hash(user)) {
                            snprintf(response, sizeof(response), "ERR 409 SID:%s User already exists", SID);
                        } else {
                            char *salt = generate_salt();
                            char *hashed = crypt(pass, salt);
                            save_user_hash(user, hashed);
                            snprintf(response, sizeof(response), "OK 200 SID:%s Registration successful", SID);
                        }
                        log_event(client_ip, client_port, child_pid, words[1], payload, response);
                    }
                    send(client_fd, response, strlen(response), 0);

                } else if (strcmp(cmd, "LOGIN") == 0) {
                    if (word_count < 3 || !validate_username(words[1])) {
                        snprintf(response, sizeof(response), "ERR 400 SID:%s Invalid username or usage", SID);
                    } else {
                        char *user = words[1];
                        char *pass = words[2];
                        char *stored = get_user_hash(user);

                        if (!stored || strcmp(crypt(pass, stored), stored) != 0) {
                            failed_logins++;
                            snprintf(response, sizeof(response), "ERR 401 SID:%s Invalid credentials", SID);
                            if (failed_logins >= 3) {
                                snprintf(response, sizeof(response), "ERR 423 SID:%s Account locked (brute-force)", SID);
                            }
                        } else {
                            snprintf(session_token, sizeof(session_token), "TOK-%s-%ld", user, time(NULL) % 1000000);
                            if (username) free(username);
                            username = strdup(user);
                            failed_logins = 0;
                            snprintf(response, sizeof(response), "OK 200 SID:%s Login successful token:%s", SID, session_token);
                        }
                        log_event(client_ip, client_port, child_pid, user, payload, response);
                    }
                    send(client_fd, response, strlen(response), 0);

                } else if (strcmp(cmd, "LOGOUT") == 0) {
                    if (username) free(username);
                    username = NULL;
                    strcpy(session_token, "");
                    snprintf(response, sizeof(response), "OK 200 SID:%s Logout successful", SID);
                    send(client_fd, response, strlen(response), 0);
                    log_event(client_ip, client_port, child_pid, "-", payload, response);

                } else {
                    snprintf(response, sizeof(response), "OK 200 SID:%s Command accepted", SID);
                    send(client_fd, response, strlen(response), 0);
                    log_event(client_ip, client_port, child_pid, username, payload, response);
                }
            }
            close(client_fd);
            if (username) free(username);
            exit(0);
        } else {
            close(client_fd);
        }
    }
    fclose(log_fp);
    close(server_fd);
    return 0;
}
