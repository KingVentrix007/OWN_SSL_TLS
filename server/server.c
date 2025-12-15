#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> // For close()
#include "include/packet_headers.h"
#include <arpa/inet.h>
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include <openssl/pem.h>
#include "include/rsakey.h"
#include <uuid/uuid.h>
#include "openssl/rsa.h"
RSA *global_rsa_keypair;

void setup_rsa()
{
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    global_rsa_keypair = RSA_new();
    RSA_generate_key_ex(global_rsa_keypair, 2048, e, NULL);

    BN_free(e);
}




int send_packet(int sock, uint32_t type, const void *data, uint32_t size)
{


    return 0;
}



int send_rsa_key(int socket_number)
{
        int rsa_key_size;
        unsigned char *rsa_pub_key = serialize_rsa_pubkey(global_rsa_keypair,&rsa_key_size);
        size_t pkt_size;
        int err;
        uint8_t *send_rsa_packet = build_packet(0,SEND_RSA,0,0,NULL,rsa_key_size,rsa_pub_key,&pkt_size,&err);
        send(socket_number, send_rsa_packet, pkt_size, 0); // Send data
}

int handle_get_aes(int socket_number,packet_t pkt)
{
    uuid_t binuuid;
    char uuid_str[37]; // Users UUID
    uuid_generate_random(binuuid);
    uuid_unparse(binuuid, uuid_str);
    int encrypted_length = RSA_size(global_rsa_keypair);

    unsigned char *decrypted_data = malloc((size_t)encrypted_length);
    // int decrypted_length = RSA_public_encrypt(32,aes_key,encrypted_aes_key,server_rsa_key,PADDING);
    int decrypted_length = RSA_private_decrypt(encrypted_length,pkt.payload,decrypted_data,global_rsa_keypair,RSA_PKCS1_OAEP_PADDING);

}

int handle_connection(int socket)
{
    while(1==1)
    {
        size_t buffer_size;
        uint8_t *buffer = get_pkt(socket,&buffer_size);
        packet_t pkt;
        if(buffer == NULL)
        {
            // printf("Issue with buffer\n");
            //There is no packet;
        }
        else
        {
            int err = decode_packet(buffer,buffer_size,&pkt);
            printf("Packet_type(server) = %d\n",pkt.type);
            if(pkt.type == GET_RSA)
            {
                
                send_rsa_key(socket);
            }
            else if (pkt.type == SEND_AES)
            {
                printf("HERE\n");
                handle_get_aes(socket,pkt);
            }
        }
        
    }
        
        
}

int start_server()
{
    setup_rsa();
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    server_addr.sin_port = htons(8080); // Use port 8080 (example)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) { // 10 is the backlog queue size
    perror("listen failed");
    exit(EXIT_FAILURE);
    }
    printf("Server listening on port 8080...\n");
    while(1==1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (new_socket < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }
        printf("Client connected.\n");
        handle_connection(new_socket);

        
    }
}

int main(int argc, char const *argv[])
{
    start_server();
    return 0;
}
