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
    payload->maskKey[0] = (char)rand() % 255;
    srand(time(NULL)+payload->maskKey[0]);
    payload->maskKey[1] = (char)rand() % 255;
    srand(time(NULL)+payload->maskKey[0]+payload->maskKey[1]);
    payload->maskKey[2] = (char)rand() % 255;
    srand(time(NULL)+payload->maskKey[0]+payload->maskKey[1]+payload->maskKey[2]);
    payload->maskKey[3] = (char)rand() % 255;
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


        if (payload_getLength(payload) <= 125) {
            i_payload = ((i_payload) << 7) | (payload_getLength(payload));
            o_payload = ((i_payload >> 8) & 0x00FF);
            i_payload = i_payload & 0x00FF;
        } else if (payload_getLength(payload) <= 0xffff) {
            i_payload = ((i_payload) << 7) | 126;
            o_payload = 0;
           // i_payload = pack('n', i_payload).pack('n*', payload_getLength(payload));
        } else {
            i_payload = ((i_payload) << 7) | 127;
            o_payload = 0;
            /*$left = 0xffffffff00000000;
            $right = 0x00000000ffffffff;
            $l = (payload->getLength() & $left) >> 32;
            $r = payload->getLength() & $right;
            i_payload = pack('n', i_payload).pack('NN', $l, $r);*/
        }

        char * data = malloc(payload_getLength(payload));
        bzero(data,strlen(data));

        char auxpayload[4086];
        int size = 0;
        char aux_unit[2];
        aux_unit[0] = (char)o_payload;
        aux_unit[1] = (char)i_payload;

        if (payload_getMask(payload) == 0x1) {
            payload_maskData(payload, data);
            memcpy(auxpayload, aux_unit, 2);
            memcpy(&auxpayload[2], payload_getMaskKey(payload), 4);
            memcpy(&auxpayload[6], data, strlen(data));
            size = 6 + strlen(data);

        } else {
            //data = payload_getPayload(payload);
            memcpy(auxpayload, aux_unit, 2);
            memcpy(&auxpayload[2], (const char * )payload->payload, strlen((const char * )payload->payload));
            size = 2 + strlen((const char * )payload->payload);
        }


    payload->enc_payload_size = size;
    char * encoded_payload = malloc(size);
    bzero(encoded_payload,strlen(encoded_payload));
    memcpy(encoded_payload,auxpayload,size);

    return encoded_payload;

}
