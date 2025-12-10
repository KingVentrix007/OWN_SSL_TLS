#ifndef __PACKET_HEADERS__H
#define __PACKET_HEADERS__H


enum PacketTypes
{
    GET_RSA = 1,
    SEND_RSA = 2,
    
};
typedef struct {
    uint16_t version;
    uint8_t type;
    uint32_t packet_size;
    uint8_t auth_type;
    uint32_t auth_len;
    uint32_t *auth;      // dynamically allocated
    uint32_t payload_len;
    uint8_t *payload;    // dynamically allocated
} packet_t;

int decode_packet(uint8_t *buffer, size_t buffer_len, packet_t *pkt);
uint8_t *build_packet(uint16_t version,uint8_t type,uint8_t auth_type,uint32_t auth_len,uint32_t auth[],uint32_t payload_len,uint8_t payload[],size_t *out_len, int *err);
uint8_t *get_pkt(int socket,size_t *buffer_len);

#endif