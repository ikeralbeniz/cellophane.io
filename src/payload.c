/*
 * cellophane.io - simple socket.io client writen in c
 *
 * Copyright (C) 2014 Iker Perez de Albeniz <iker.perez.albeniz@gmail.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include <wchar.h>
#include <time.h>
#include <stdlib.h>

#include "payload.h"


#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0)

void payload_init(Payload * payload){

    payload->fin = 0x1;
    payload->rsv1 = 0x0;
    payload->rsv2 = 0x0;
    payload->rsv3 = 0x0;
    payload->mask = 0x0;
    payload->enc_payload_size = 0;
}

void payload_setFin(Payload * payload, int fin) {
    payload->fin = fin;
}

int payload_getFin(Payload * payload) {
    return payload->fin;
}

void payload_setRsv1(Payload * payload, int rsv1) {
    payload->rsv1 = rsv1;
}


int payload_getRsv1(Payload * payload) {
    return payload->rsv1;
}

void payload_setRsv2(Payload * payload, int rsv2) {
    payload->rsv2 = rsv2;
}

int payload_getRsv2(Payload * payload) {
    return payload->rsv2;
}

void payload_setRsv3(Payload * payload, int rsv3) {
    payload->rsv3 = rsv3;
}

int payload_getRsv3(Payload * payload) {
    return payload->rsv3;
}

void payload_setOpcode(Payload * payload, int opcode) {
    payload->opcode = opcode;
}

int payload_getOpcode(Payload * payload) {
    return payload->opcode;
}


void payload_setMask(Payload * payload, int mask) {
    payload->mask = mask;

    if (payload->mask) {
       payload_generateMaskKey(payload);
    }
}

int payload_getMask(Payload * payload) {
    return payload->mask;
}

int payload_getLength(Payload * payload) {
    return (int) strlen((const char *)payload->payload);
}

void payload_setMaskKey(Payload * payload, unsigned char * maskKey) {

    memcpy(payload->maskKey, maskKey, 4);
}

unsigned char * payload_getMaskKey(Payload * payload) {
        return payload->maskKey;
}

void payload_setPayload(Payload * payload, unsigned char * v_payload) {
    payload->payload = malloc((int)strlen((const char *)v_payload));
    sprintf((char *)payload->payload,"%s",v_payload);
}

unsigned char *  payload_getPayload(Payload * payload) {
    return payload->payload;
}

void payload_generateMaskKey(Payload * payload){

    srand(time(NULL));
    payload->maskKey[0] = (char)rand() % 126;
    srand(time(NULL)+payload->maskKey[0]);
    payload->maskKey[1] = (char)rand() % 126;
    srand(time(NULL)+payload->maskKey[0]+payload->maskKey[1]);
    payload->maskKey[2] = (char)rand() % 126;
    srand(time(NULL)+payload->maskKey[0]+payload->maskKey[1]+payload->maskKey[2]);
    payload->maskKey[3] = (char)rand() % 126;
}

void payload_maskData(Payload * payload, char * masked) {

    int i;
    int j = payload_getLength(payload);

    char x;
    for (i = 0; i < j; i++) {
        masked[i] = *(payload->payload+i) ^ *(payload->maskKey+(i % 4));
    }

}

unsigned char * payload_encodePayload(Payload * payload)
{



        int i_payload;
        int o_payload;

        i_payload = ((payload_getFin(payload)) << 1) | (payload_getRsv1(payload));
        i_payload = ((i_payload) << 1) | (payload_getRsv2(payload));
        i_payload = ((i_payload) << 1) | (payload_getRsv3(payload));
        i_payload = ((i_payload) << 4) | (payload_getOpcode(payload));
        i_payload = ((i_payload) << 1) | (payload_getMask(payload));


        int aux_unit_len = 0;
        char auxpayload[4096];
        bzero(auxpayload,4096);

        if (payload_getLength(payload) <= 125) {

            i_payload = ((i_payload) << 7) | (payload_getLength(payload));

            char aux_unit_125[2];
            aux_unit_125[0] = (char)((i_payload >> 8) & 0x00FF);;
            aux_unit_125[1] = (char)i_payload & 0x00FF;;

            memcpy(auxpayload, aux_unit_125, 2);
            aux_unit_len = 2;

        } else if (payload_getLength(payload) <= 0xffff) {
            i_payload = ((i_payload) << 7);

            char aux_unit_127[4];

            aux_unit_127[0] = (char)((i_payload >> 8) & 0x00FF);
            aux_unit_127[1] = (char) 0x00FE;

            int l_payload = payload_getLength(payload);

            aux_unit_127[2] = (char)((l_payload >> 8) & 0x00FF);
            aux_unit_127[3] = (char)l_payload & 0x00FF;

            memcpy(auxpayload, aux_unit_127, 4);
            aux_unit_len = 4;

           // i_payload = pack('n', i_payload).pack('n*', payload_getLength(payload));
        } else {
            printf("--> Super Extended Payload\n");
            i_payload = ((i_payload) << 7) | 127;
            o_payload = 0;
            /*$left = 0xffffffff00000000;
            $right = 0x00000000ffffffff;
            $l = (payload->getLength() & $left) >> 32;
            $r = payload->getLength() & $right;
            i_payload = pack('n', i_payload).pack('NN', $l, $r);*/
            aux_unit_len = 8;
        }

        char * data = malloc(payload_getLength(payload));
        bzero(data,strlen(data));


        int size = 0;


        if (payload_getMask(payload) == 0x1) {
            payload_maskData(payload, data);
            memcpy(&auxpayload[aux_unit_len], payload_getMaskKey(payload), 4);
            memcpy(&auxpayload[aux_unit_len+4], data, strlen(data));
            size = aux_unit_len + 4 + payload_getLength(payload);

        } else {
            //data = payload_getPayload(payload);
            //memcpy(auxpayload, aux_unit, 2);
            memcpy(&auxpayload[aux_unit_len], (const char * )payload->payload, strlen((const char * )payload->payload));
            size = aux_unit_len + payload_getLength(payload);
        }

    payload->enc_payload_size = size;
    char * encoded_payload = malloc(size);
    bzero(encoded_payload,strlen(encoded_payload));
    memcpy(encoded_payload,auxpayload,size);

    return encoded_payload;

}
