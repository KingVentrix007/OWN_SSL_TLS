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

RSA *global_rsa_keypair;

int setup_rsa()
{
    global_rsa_keypair = RSA_generate_key(2048, RSA_F4, NULL, NULL);
}

unsigned char *serialize_rsa_pubkey(RSA *rsa, int *rsa_key_size)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio,rsa);
    unsigned char *data;
    *rsa_key_size = BIO_get_mem_data(bio,&data);
    unsigned char *key_out = malloc(*rsa_key_size);
    memcpy(key_out,data,*rsa_key_size);
    BIO_free(bio);
    return key_out;
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
        size_t buffer_size;
        uint8_t *buffer = get_pkt(new_socket,&buffer_size);
        packet_t pkt;
        if(buffer == NULL)
        {
            printf("Issue with buffer\n");
        }
        int err = decode_packet(buffer,buffer_size,&pkt);
        printf("Packet_type = %d\n",pkt.type);
        if(pkt.type = GET_RSA)
        {
            

        }
    }
    
    // char recv_buffer[sizeof(get_rsa_packet_t)] = {0};

    // // Receive data
    // recv(new_socket, recv_buffer, sizeof(get_rsa_packet_t),0);
    // get_rsa_packet_t get_rsa_packet;
    // int offset = 0;
    // uint32_t packet_type_recv;
    // memcpy(&packet_type_recv, recv_buffer + offset, sizeof(packet_type_recv));
    // get_rsa_packet.packet_type = ntohl(packet_type_recv);
    // offset += sizeof(packet_type_recv);
    // memcpy(get_rsa_packet.packet_type_str, recv_buffer + offset, sizeof(get_rsa_packet.packet_type_str));
    // offset += sizeof(get_rsa_packet.packet_type_str);
    // printf("Packet Type: %s | %d\n",get_rsa_packet.packet_type_str,get_rsa_packet.packet_type);
    // RSA *public_rsa = RSAPublicKey_dup(global_rsa_keypair);
    // int key_size;
    // unsigned char *rsa_socket_public_key = serialize_rsa_pubkey(public_rsa,&key_size);
    
    



    


 
}

int main(int argc, char const *argv[])
{
    start_server();
    return 0;
}
