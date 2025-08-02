//#include "auth_client.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/md5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "auth_user.h"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9999

void md5_encrypt(const char *input, char *output) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[32] = '\0';
}


void get_hash(char* username, char* password, char* hash){
    //conctination
    char concated[256];
    snprintf(concated, sizeof(concated),"%s%s", password, username);
    char md5_hash[33];
    md5_encrypt(concated, md5_hash);


    //char final_hash[37];
    snprintf(hash, 37, "md5%s", md5_hash);
}

int auth_req(char* username, char* password){
    if(!username || !password){
    	printf("Usage: <username> <password>\n");
	return 0;
    }
    int server_socket;
    struct sockaddr_in server_addr;
    int connection_result;
    char hash[37];
    char buffer[512];
    char get;
    get_hash(username,password,hash);
    snprintf(buffer, sizeof(buffer),"%s:%s",username,hash);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connection_result = connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    if (connection_result == -1) {
        perror("Error:");
	close(server_socket);
        exit(1);
    }

    write(server_socket, buffer, sizeof(buffer) - 1);
    memset(buffer,0,sizeof(buffer));
    if(read(server_socket, &get, sizeof(get)) == -1){
        perror("Error:");
	close(server_socket);
	return 1;	
    }
    
    if((int)get != 1){
    	return 1;
    }
    close(server_socket);

    return 0;
}
