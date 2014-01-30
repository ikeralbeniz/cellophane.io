#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_


enum payload_opcodes{
    
    OPCODE_CONTINUE = 0x0,
    OPCODE_TEXT = 0x1,
    OPCODE_BINARY = 0x2,
    OPCODE_NON_CONTROL_RESERVED_1 = 0x3,
    OPCODE_NON_CONTROL_RESERVED_2 = 0x4,
    OPCODE_NON_CONTROL_RESERVED_3 = 0x5,
    OPCODE_NON_CONTROL_RESERVED_4 = 0x6,
    OPCODE_NON_CONTROL_RESERVED_5 = 0x7,
    OPCODE_CLOSE = 0x8,
    OPCODE_PING = 0x9,
    OPCODE_PONG = 0xA,
    OPCODE_CONTROL_RESERVED_1 = 0xB,
    OPCODE_CONTROL_RESERVED_2 = 0xC,
    OPCODE_CONTROL_RESERVED_3 = 0xD,
    OPCODE_CONTROL_RESERVED_4 = 0xE,
    OPCODE_CONTROL_RESERVED_5 = 0xF,
};

typedef struct _payload{

    int fin;
    int rsv1;
    int rsv2;
    int rsv3 ;
    int opcode;
    int mask;
    unsigned char maskKey[4];
    unsigned char * payload;
    int enc_payload_size;


} payload_type;

typedef payload_type Payload;


void payload_init(Payload * payload);
void payload_setFin(Payload * payload, int fin);
int payload_getFin(Payload * payload);
void payload_setRsv1(Payload * payload, int rsv1);
int payload_getRsv1(Payload * payload);
void payload_setRsv2(Payload * payload, int rsv2);
int payload_getRsv2(Payload * payload);
void payload_setRsv3(Payload * payload, int rsv3);
int payload_getRsv3(Payload * payload);
void payload_setOpcode(Payload * payload, int opcode);
int payload_getOpcode(Payload * payload);
void payload_setMask(Payload * payload, int mask);
int payload_getMask(Payload * payload);
int payload_getLength(Payload * payload);
void payload_setMaskKey(Payload * payload, unsigned char * maskKey);
unsigned char * payload_getMaskKey(Payload * payload);
void payload_setPayload(Payload * payload, unsigned char * v_payload);
unsigned char *  payload_getPayload(Payload * payload);
void payload_generateMaskKey(Payload * payload);
void payload_maskData(Payload * payload, char * masked);
unsigned char * payload_encodePayload(Payload * payload);


#endif
