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

#define PORT_NUMBER 8080
#define VERSION 1





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

int init_connection(int socket_number)
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
    printf("Packet_type = %d\n",pkt.type);
    if(pkt.type != SEND_RSA)
    {
        return -1;
    }
    char *rsa_key = malloc(pkt.payload_len);
    strncpy(rsa_key,pkt.payload,pkt.payload_len);
    printf("client:\n%s\n",rsa_key);

        
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
