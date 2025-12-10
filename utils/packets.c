#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_addr
#include <netdb.h>     // For gethostbyname (optional, for domain names)
#include "include/packet_headers.h"
// [version]
// [type]
// [auth_type]
// [auth_len]
// [auth[]]
// [payload_len] //Encryption happens from here
// [payload]
// [checksum]
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h> // For PRIu32
uint8_t *build_packet(uint16_t version,uint8_t type,uint8_t auth_type,uint32_t auth_len,uint32_t auth[],uint32_t payload_len,uint8_t payload[],size_t *out_len, int *err) 
{
    size_t bsize =
        sizeof(uint16_t) +   // version
        sizeof(uint8_t)  +   // type
        sizeof(uint32_t) + //Packet size
        sizeof(uint8_t)  +   // auth_type
        sizeof(uint32_t) +   // auth_len
        auth_len * sizeof(uint32_t) +
        sizeof(uint32_t) +   // payload_len
        payload_len;

    size_t offset = 0;
    uint8_t *buffer = malloc(bsize);
    if (!buffer) {
        *err = -1;
        return NULL;
    }

    // Convert to network byte order
    uint16_t net_version     = htons(version);
    uint32_t net_auth_len    = htonl(auth_len);
    uint32_t net_payload_len = htonl(payload_len);
    if (bsize > UINT32_MAX) {
        *err = -2; // packet too big
        free(buffer);
        return NULL;
    }
    uint32_t net_bsize = htonl((uint32_t)bsize);


    memcpy(buffer + offset, &net_version, sizeof(net_version));
    offset += sizeof(net_version);

    memcpy(buffer + offset, &type, sizeof(type));
    offset += sizeof(type);

    memcpy(buffer+offset,&net_bsize,sizeof(uint32_t));
    offset+=sizeof(net_bsize);
    memcpy(buffer + offset, &auth_type, sizeof(auth_type));
    offset += sizeof(auth_type);

    memcpy(buffer + offset, &net_auth_len, sizeof(net_auth_len));
    offset += sizeof(net_auth_len);

    // auth[] values also need byte-order conversion
    for (uint32_t i = 0; i < auth_len; i++) {
        uint32_t net_auth = htonl(auth[i]);
        memcpy(buffer + offset, &net_auth, sizeof(net_auth));
        offset += sizeof(net_auth);
    }

    memcpy(buffer + offset, &net_payload_len, sizeof(net_payload_len));
    offset += sizeof(net_payload_len);

    memcpy(buffer + offset, payload, payload_len);
    offset += payload_len;

    *out_len = offset;
    *err = 0;
    return buffer;
}


uint8_t *get_pkt(int socket,size_t *buffer_len)
{
    uint8_t buf[7];
    size_t received = 0;

    while(received < sizeof(buf)) {
        ssize_t r = recv(socket, buf + received, sizeof(buf) - received, 0);
        if(r <= 0) {
            return NULL; // error or connection closed
        }
        received += r;
    }
    // printf("GOT %ld bytes\n",received);
    uint16_t tmp_ver;
    uint32_t tmp_size;

    memcpy(&tmp_ver, buf, sizeof(uint16_t));
    memcpy(&tmp_size, buf + sizeof(uint16_t)+sizeof(uint8_t), 4);

    uint16_t version = ntohs(tmp_ver);
    uint8_t type = buf[2];
    uint32_t pkt_size = ntohl(tmp_size);
    uint8_t *final_buffer = malloc(pkt_size);
    // printf("PKT_SZIE = %u\n", pkt_size);

    memcpy(final_buffer,buf,received);
    while(received < pkt_size) {
        ssize_t r = recv(socket, final_buffer + received, pkt_size - received, 0);
        if(r <= 0) {
            return NULL; // error or connection closed
        }
        received += r;
    }
    // printf("PKT SIZE: %")
    *buffer_len = pkt_size;
    return final_buffer;
    
}

int decode_packet(uint8_t *buffer, size_t buffer_len, packet_t *pkt) {
    if (!buffer || !pkt) return -1;

    size_t offset = 0;

    if (buffer_len < sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t))
        return -2; // buffer too small

    // version
    uint16_t net_version;
    memcpy(&net_version, buffer + offset, sizeof(net_version));
    pkt->version = ntohs(net_version);
    offset += sizeof(net_version);

    // type
    memcpy(&pkt->type, buffer + offset, sizeof(pkt->type));
    offset += sizeof(pkt->type);

    // packet size
    uint32_t net_packet_size;
    memcpy(&net_packet_size, buffer + offset, sizeof(net_packet_size));
    pkt->packet_size = ntohl(net_packet_size);
    offset += sizeof(net_packet_size);

    if (pkt->packet_size > buffer_len)
        return -3; // malformed packet

    // auth_type
    memcpy(&pkt->auth_type, buffer + offset, sizeof(pkt->auth_type));
    offset += sizeof(pkt->auth_type);

    // auth_len
    uint32_t net_auth_len;
    memcpy(&net_auth_len, buffer + offset, sizeof(net_auth_len));
    pkt->auth_len = ntohl(net_auth_len);
    offset += sizeof(net_auth_len);

    // auth array
    if (pkt->auth_len > 0) {
        pkt->auth = malloc(pkt->auth_len * sizeof(uint32_t));
        if (!pkt->auth) return -4; // allocation failed
        for (uint32_t i = 0; i < pkt->auth_len; i++) {
            uint32_t net_auth;
            memcpy(&net_auth, buffer + offset, sizeof(net_auth));
            pkt->auth[i] = ntohl(net_auth);
            offset += sizeof(net_auth);
        }
    } else {
        pkt->auth = NULL;
    }

    // payload_len
    uint32_t net_payload_len;
    memcpy(&net_payload_len, buffer + offset, sizeof(net_payload_len));
    pkt->payload_len = ntohl(net_payload_len);
    offset += sizeof(net_payload_len);

    // payload
    if (pkt->payload_len > 0) {
        pkt->payload = malloc(pkt->payload_len);
        if (!pkt->payload) {
            free(pkt->auth);
            return -5; // allocation failed
        }
        memcpy(pkt->payload, buffer + offset, pkt->payload_len);
        offset += pkt->payload_len;
    } else {
        pkt->payload = NULL;
    }

    return 0; // success
}