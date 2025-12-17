#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_addr
#include "include/packet_headers.h"
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include "include/rsakey.h"
#include "include/security.h"
#include "include/serverheaders.h"
#define PORT_NUMBER 8080
#define VERSION 1
#define PADDING RSA_PKCS1_OAEP_PADDING
RSA *server_rsa_key;
client_t client_data;




int send_data(int socket_number,const char *message)
{
    printf("Connected to server.\n");
    send(socket_number, message, strlen(message), 0); // Send data
    return 0;
}
int close_connect(int socket_number)
{
    close(socket_number);
}


int get_rsa_key(int socket_number)
{
    //Fetch RSA KEY
    size_t packet_size;
    int err;
    uint8_t *get_rsa_packet = build_packet(0,GET_RSA,0,0,NULL,0,NULL,&packet_size,&err);
    if(err != 0)
    {
        return -1;
    }
    send(socket_number, get_rsa_packet, packet_size, 0); // Send data
    size_t buffer_size;
    uint8_t *buffer = get_pkt(socket_number,&buffer_size);
    packet_t pkt;
    if(buffer == NULL)
    {
        printf("Issue with buffer\n");
    }
    int decode_err = decode_packet(buffer,buffer_size,&pkt);
    printf("Packet_type(client) = %d\n",pkt.type);
    if(pkt.type != SEND_RSA)
    {
        return -1;
    }
    char *rsa_key = malloc(pkt.payload_len);
    strncpy(rsa_key,pkt.payload,pkt.payload_len);
    // printf("client:\n%s\n",rsa_key);
    server_rsa_key = load_pem_rsa_key_pub(rsa_key);
}
int send_aes_key(int socket_number)
{
    int err;
    size_t packet_size;

    unsigned char *aes_key = generate_key(32);
    int encrypted_length = RSA_size(server_rsa_key);
    unsigned char *encrypted_aes_key = (unsigned char*)malloc(encrypted_length);
    encrypted_length = RSA_public_encrypt(32,aes_key,encrypted_aes_key,server_rsa_key,PADDING);
    uint8_t *send_aes_packet = build_packet(0,SEND_AES,0,0,NULL,encrypted_length,encrypted_aes_key,&packet_size,&err);
    printf("sending\n");
    send(socket_number, send_aes_packet, packet_size, 0); // Send aes_key


    size_t buffer_size;
    uint8_t *buffer = get_pkt(socket_number,&buffer_size);
    packet_t pkt;
    if(buffer == NULL)
    {
        printf("Issue with buffer\n");
    }
    int decode_err = decode_packet(buffer,buffer_size,&pkt);
    printf("Packet_type(client) = %d\n",pkt.type);
    if(pkt.type == ACK_AES)
    {
        unsigned char *output_text = malloc(pkt.payload_len);
        
        // printf("Starting dec\n");
        aes_dec(pkt.payload,pkt.payload_len,output_text,aes_key);
        strcpy(client_data.uuid_str,output_text);
        client_data.aes_key = malloc(33);
        memcpy(client_data.aes_key,aes_key,32);

        printf("UUID: %s\n",client_data.uuid_str);

    }
}

int request_certificate(int socket_number)
{
    int err;
    size_t packet_size;
    
    unsigned char *enc_uuid;
    uint32_t enc_uuid_len;
    printf("Starting\n");
    enc_uuid = aes_enc(client_data.uuid_str,strlen(client_data.uuid_str),client_data.aes_key,&enc_uuid_len);

    uint8_t *get_cert_packet = build_packet(0,REQUEST_CERT,PRE_CERT,enc_uuid_len,(uint8_t *)enc_uuid,0,NULL,&packet_size,&err);
    send(socket_number,get_cert_packet,packet_size,0);

    size_t buffer_size;
    uint8_t *buffer = get_pkt(socket_number,&buffer_size);
    packet_t pkt;
    if(buffer == NULL)
    {
        printf("Issue with buffer\n");
    }
    int decode_err = decode_packet(buffer,buffer_size,&pkt);
    
    

}

int init_connection(int socket_number)
{
    get_rsa_key(socket_number);
    printf("SEND aes\n");
    send_aes_key(socket_number);
    printf("Request Cert\n");
    request_certificate(socket_number);
    
        
}

int setup_client()
{


    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address)); // Clear the structure
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT_NUMBER); // Convert port to network byte order
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Error connecting to server");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    init_connection(client_socket);
}

int main(int argc, char const *argv[])
{
    setup_client();
    return 0;
}
