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

#include <sys/select.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <wchar.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <string.h>
#include <unistd.h>

#include "cellophane_io.h"
#include "md5.h"

/* function prototypes to define later */
int Base64encode_len(int len);
int Base64encode(char *encoded, const char *string, int len);
int cellophane_read_ready(WsHandler * ws_handler);
void cellophane_reconect(WsHandler * ws_handler);
void cellophane_compute_md5(char *str, unsigned char digest[16]);
int cellophane_number_of_message(char * buffer, int n);
int cellophane_find_on_char_array(char ** tokens , char * key);
char** cellophane_str_split(char* a_str, const char a_delim);
char * cellophane_do_web_request(WsHandler * ws_handler);
size_t static cellophane_write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp);

int findn(int num)
{
    int n = 0;
    while(num) {
        num /= 10;
        n++;
    }
    return n;
}

void cellophane_io(WsHandler * ws_handler, char * tcp_protocol, char * address, int port ){

    cellophane_new(ws_handler, tcp_protocol, address, port, "socket.io", 1, 0, 1, 0);
    cellophane_init(ws_handler, 0);

}

void cellophane_new(WsHandler * ws_handler, char * tcp_protocol , char * address, int port, char * path, int protocol, int read, int  checkSslPeer, int debug){

    int url_size = (int)(strlen(tcp_protocol) + strlen(address) + strlen(path) + findn(port) + findn(protocol) ) + 3;
    ws_handler->socketIOUrl = malloc(url_size);
    sprintf(ws_handler->socketIOUrl,"%s%s:%d/%s/%d", tcp_protocol, address, port, path, protocol);
    ws_handler->serverHost = address;
    ws_handler->serverPort = port;
    int path_size = (int)(strlen(path) + findn(protocol) ) + 2;
    ws_handler->serverPath = malloc(path_size);
    sprintf(ws_handler->serverPath,"/%s/%d",path, protocol);
    ws_handler->read = read;
    ws_handler->debug =debug;
    ws_handler->checkSslPeer = checkSslPeer;

    ws_handler->lastId = 0;
    ws_handler->checkSslPeer = 1;
    ws_handler->handshakeTimeout = NULL;

}

void cellophane_init(WsHandler * ws_handler, int keepalive){

    cellophane_handshake(ws_handler);
    cellophane_connect(ws_handler);
    if (keepalive) {
        cellophane_keepAlive(ws_handler);
    }
}


int cellophane_handshake(WsHandler * ws_handler) {

    char * res = cellophane_do_web_request(ws_handler);
    if (res == NULL || strcmp(res,"") == 0){
        return 0;
    }

    char** tokens;
    tokens = cellophane_str_split(res, ':');

    if (tokens)
    {
        int i;
        for (i = 0; *(tokens + i); i++)
        {
            if(i== 0){
                ws_handler->session.sid = malloc(strlen(*(tokens + i)));
                memcpy(ws_handler->session.sid, *(tokens + i), strlen(*(tokens + i)) );
            }

            if(i== 1){
                ws_handler->session.heartbeat_timeout = atoi(*(tokens + i));
            }

            if(i== 2){
                ws_handler->session.connection_timeout = atoi(*(tokens + i));

            }

            if(i== 3){
                ws_handler->session.supported_transports = cellophane_str_split(*(tokens + i),',');
            }

            //free(*(tokens + i));
        }
        //free(tokens);
    }

    if(!cellophane_find_on_char_array(ws_handler->session.supported_transports, "websocket")){
        return 0;
    }

    return 1;
}


int cellophane_connect(WsHandler * ws_handler) {

    int portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buff[256];


    portno = ws_handler->serverPort;

    ws_handler->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ws_handler->fd < 0)
    {
        perror("ERROR opening socket");
        ws_handler->fd_alive = 0;
        exit(1);
    }

    server = gethostbyname(ws_handler->serverHost);

    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        ws_handler->fd_alive = 0;
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);



    if (connect(ws_handler->fd,(const struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
    {
         perror("ERROR connecting");
         ws_handler->fd_alive = 0;
         exit(1);
    }

    ws_handler->fd_alive = 1;

    char * key = cellophane_generateKey(16);

    int out_len = (int)(strlen(ws_handler->serverPath) + strlen(ws_handler->session.sid) + strlen(ws_handler->serverHost) + strlen(key) ) + 136;
    char * out = malloc(out_len);
    bzero(out,out_len);
    sprintf(out, "GET %s/websocket/%s HTTP/1.1\r\nHost: %s\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nOrigin: *\r\n\r\n",
        ws_handler->serverPath,
        ws_handler->session.sid,
        ws_handler->serverHost,
        key);

    n = send(ws_handler->fd,out,out_len, 0);
    //printf("sending data line 196\n");
    if (n < 0)
    {
         perror("ERROR writing to socket");
         ws_handler->fd_alive = 0;
         exit(1);
    }

    bzero(buff,256);
    n = recv(ws_handler->fd,buff,255, 0);
    if (n < 0)
    {
         perror("ERROR reading from socket");
         ws_handler->fd_alive = 0;
         exit(1);
    }

    ws_handler->buffer = realloc(NULL, strlen(buff));
    strcpy(ws_handler->buffer, buff);



    if(strncmp (ws_handler->buffer,"HTTP/1.1 101",12) != 0){
        perror("Unexpected Response. Expected HTTP/1.1 101..\nAborting...");
        ws_handler->fd_alive = 0;
        exit(1);
    }

    char * m_payload;
    char ** m_payload_a;

    if(strstr(ws_handler->buffer,"1::") == NULL){

        while(!cellophane_read_ready(ws_handler)){
            usleep(100*1000);

        }

        int msg_number = 0;
        m_payload_a = cellophane_read(ws_handler,&msg_number);
        m_payload = *(m_payload_a);
        //m_payload_a--;

        /* const char** ptr = mpg123_decoders();
        int count = 0;
        while (*(ptr++) != NULL){ ++count; }
            --ptr;
        while (count-- > 0){
        syslog(LOG_DEBUG, "\t%s",*(--ptr));
        }*/

    }else{

        m_payload = strstr(ws_handler->buffer,"1::");
    }

    if(strncmp (m_payload,"1::",3) != 0){
        perror("Socket.io did not send connect response. Aborting...");
        ws_handler->fd_alive = 0;
        exit(1);
    }else{
        printf("Conection stablished...\n",m_payload);
    }



    ws_handler->heartbeatStamp = time(NULL);

    //free(m_payload_a);
    //free(m_payload);

}

char * cellophane_generateKey(int length) {

        char * key;
        int c = 0;
        char * tmp = malloc(16);
        unsigned char * digest = malloc(16);
        char random_number[16];
        strcpy(tmp, "");

        while( (c * 16) < length) {
            tmp = realloc(tmp,(c+1)*16);
            srand(time(NULL));
            sprintf(random_number,"%d",rand());
            cellophane_compute_md5((char *)random_number,digest);
            strcat(tmp, (const char *)digest);
            c++;
        }


        key = malloc(Base64encode_len(c*16));
        Base64encode(key, tmp, c*16);

        return key;

}

char ** cellophane_read(WsHandler * ws_handler, int * message_num) {

        int n;
        int totalread = 0;
        char * m_payload;
        char buff[256];


        bzero(buff,256);
        n = recv(ws_handler->fd,buff,1, 0);
        if (n < 0)
        {
             perror("ERROR reading from socket");
             exit(1);
        }

        bzero(buff,256);
        n = recv(ws_handler->fd,buff,255, 0);
        if (n < 0)
        {
             perror("ERROR reading from socket");
             exit(1);
        }

        ws_handler->buffer = realloc(NULL, strlen(buff));
        strcpy(ws_handler->buffer, buff);


        int num_messages = cellophane_number_of_message(buff,n);

        while(num_messages < 0){
            //printf("\n\nNot enougth data..\n\n");
            n = n + recv(ws_handler->fd,buff,255, 0);
            if (n < 0)
            {
             perror("ERROR reading from socket");
             break;
            }
            ws_handler->buffer = (char*)realloc(ws_handler->buffer,(strlen(ws_handler->buffer) + strlen(buff)));
            strcat(ws_handler->buffer, buff);
            num_messages = cellophane_number_of_message(ws_handler->buffer,n);
        }


        char ** stream_buffer = malloc(sizeof(char*) * num_messages);

        int msg_number = 0;

        if (stream_buffer)
        {

            int buffer_pointer = 0;
            size_t idx  = 0;

            while(buffer_pointer < n){

                int payload_len = (int)(ws_handler->buffer[buffer_pointer]);
                buffer_pointer++;
                switch (payload_len) {
                    case 126:
                        {
                            char aux_len [2];
                            strncpy(aux_len, ws_handler->buffer+buffer_pointer,2);
                            payload_len = (((int)aux_len[0] & 0x00FF) << 8) | (aux_len[1]  & 0x00FF);
                            buffer_pointer = buffer_pointer + 2;
                            break;
                        }
                    case 127:
                        //perror("Next 8 bytes are 64bit uint payload length, not yet implemented, since PHP can't handle 64bit longs!");
                        break;
                }

                if((n-buffer_pointer)< payload_len){

                    printf("Not enougth data..\n");
                }

                //printf("Payload len: %d - %d\n",payload_len,n);

                char* message = malloc(payload_len+1);
                bzero(message ,payload_len);
                strncpy(message , ws_handler->buffer+buffer_pointer,payload_len);
                message[payload_len] = '\0';
                //sprintf(stream_buffer,"%s",ws_handler->buffer+1);
                buffer_pointer = buffer_pointer + payload_len +1;

                //printf("Stream buffer: %s\n",message);
                assert(idx < num_messages);
                *(stream_buffer + idx++) = strdup(message);

                msg_number++;
            }
            assert(idx == (num_messages));
            *(stream_buffer + idx) = 0;
        }


        // There is also masking bit, as MSB, but it's 0 in current Socket.io

        message_num = msg_number;

        return stream_buffer;
}


 void cellophane_send(WsHandler * ws_handler, enum socket_io_type io_type, char * id, char * endpoint, char * message) {

        Payload m_payload;
        payload_init(&m_payload);
        payload_setOpcode(&m_payload, OPCODE_TEXT);

        char * raw_message;
        if(io_type == TYPE_EVENT || io_type == TYPE_MESSAGE || io_type == TYPE_JSON_MESSAGE ){
            raw_message = malloc(4 + (int)(strlen(id)+strlen(endpoint)+strlen(message)));
            sprintf(raw_message,"%d:%s:%s:%s", io_type, id, endpoint, message);

        }else{
            raw_message = malloc(3 + (int)(strlen(id)+strlen(endpoint)));
            sprintf(raw_message,"%d:%s:%s", io_type, id, endpoint);
        }

        payload_setPayload(&m_payload,(unsigned char *)raw_message);
        payload_setMask(&m_payload, 0x1);
        int bytes_towrite;
        char * enc_payload = payload_encodePayload(&m_payload);


        int n = send(ws_handler->fd,enc_payload, m_payload.enc_payload_size, 0);
        //printf("sending data line 423\n");
        if (n < 0)
        {
            perror("ERROR writing to socket");
            exit(1);
        }
        printf("Sent    > %s\n",raw_message);
        usleep(100*1000);
}

void  cellophane_emit(WsHandler * ws_handler, char * event, char * args, char * endpoint){//, $callback = null) {

        char * message = malloc(21 + (int)(strlen(event)+strlen(args)));
        sprintf(message,"{\"name\":\"%s\",\"args\":\"%s\"}", event, args);
        cellophane_send(ws_handler,TYPE_EVENT, "", endpoint, message);
}

void cellophane_on(WsHandler * ws_handler, void (*on_event_callback)(char *))
{
    ws_handler->events[4].event_name = "default";
    ws_handler->events[4].callback_func = on_event_callback;
}

void cellophane_event_handler(WsHandler * ws_handler){


    char ** data = cellophane_read(ws_handler, NULL);

    if (data)
    {
        int i;
        for (i = 0; *(data + i); i++)
        {
            printf("Received> %s\n",*(data + i));

            if( strncmp(ws_handler->events[4].event_name,"default",7) == 0){
                ws_handler->events[4].callback_func(*(data + i));
            }
        }
    }else{

        cellophane_reconect(ws_handler);
        if(ws_handler->fd_alive){
            exit(1);
        }

        return;

    }

    /*int i = 0;
    for(i = 0; i < 128; i++){
        if(ws_handler->events[i].event_name == "notification"){
            printf("Calling function: %s\n", ws_handler->events[i].event_name);
            break;
            //(*ws_handler->events[i].callback_func)(data);
            //ws_handler->events[i].callback_func(data);
        }
    }*/



}

void  cellophane_close(WsHandler * ws_handler)
{
        cellophane_send(ws_handler, TYPE_DISCONNECT, "", "","");
        //printf("sending data line 489\n");
        close(ws_handler->fd);
}


void cellophane_reconect(WsHandler * ws_handler){

    printf("Reconecting....\n");
    cellophane_close(ws_handler);
    cellophane_connect(ws_handler);

}

void cellophane_keepAlive(WsHandler * ws_handler) {

    int result = 0;
    fd_set writefds;
    fd_set exceptfds;


    while(ws_handler->fd_alive){
        usleep(100*1000);
        while(!cellophane_read_ready(ws_handler)){
            if (ws_handler->session.heartbeat_timeout > 0 && ws_handler->session.heartbeat_timeout+ws_handler->heartbeatStamp-5 < time(NULL)) {
                cellophane_send(ws_handler, TYPE_HEARTBEAT, "", "","");
                ws_handler->heartbeatStamp = time(NULL);
            }
            usleep(100*1000);
        }
        cellophane_event_handler(ws_handler);
    }

}

int cellophane_clean_header(char * header)
{


}

int cellophane_read_ready(WsHandler * ws_handler)
{
    int iSelectReturn = 0;  // Number of sockets meeting the criteria given to select()
    struct timeval timeToWait;
    int fd_max = -1;          // Max socket descriptor to limit search plus one.
    fd_set readSetOfSockets;  // Bitset representing the socket we want to read
                              // 32-bit mask representing 0-31 descriptors where each
                              // bit reflects the socket descriptor based on its bit position.

    timeToWait.tv_sec  = 0;
    timeToWait.tv_usec = 100* 100;

    FD_ZERO(&readSetOfSockets);
    FD_SET(ws_handler->fd, &readSetOfSockets);

    if(ws_handler->fd > fd_max)
    {
       fd_max = ws_handler->fd;
    }

    iSelectReturn = select(fd_max + 1, &readSetOfSockets, (fd_set*) 0, (fd_set*) 0, &timeToWait);

    // iSelectReturn -1: ERROR, 0: no data, >0: Number of descriptors found which pass test given to select()
    if ( iSelectReturn == 0 )  // Not ready to read. No valid descriptors
    {
        return 0;
    }
    else if ( iSelectReturn < 0 )  // Handle error
    {
        return 1;
    }

    // Got here because iSelectReturn > 0 thus data available on at least one descriptor
    // Is our socket in the return list of readable sockets
    if ( FD_ISSET(ws_handler->fd, &readSetOfSockets) )
    {
        return 1;
    }
    else
    {
        return 0;
    }

    return 0;
}

/* the function to return the content for a url */
char * cellophane_do_web_request(WsHandler * ws_handler)
{

    /* keeps the handle to the curl object */
    CURL *curl_handle = NULL;
    /* to keep the response */
    char *response = NULL;

    /* initializing curl and setting the url */
    curl_handle = curl_easy_init();

    curl_easy_setopt(curl_handle, CURLOPT_URL, ws_handler->socketIOUrl );
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);

     if (!ws_handler->checkSslPeer){
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
    }

    if (ws_handler->handshakeTimeout != NULL) {
        curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT_MS, ws_handler->handshakeTimeout);
        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, ws_handler->handshakeTimeout);
    }

    /* setting a callback function to return the data */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, cellophane_write_callback_func);

    /* passing the pointer to the response as the callback parameter */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

    /* perform the request */
    int res = curl_easy_perform(curl_handle);

    /* cleaning all curl stuff */
    curl_easy_cleanup(curl_handle);

    if (res != 0 && res != 23){
        return NULL;
    }

    return response;
}

/* the function to invoke as the data recieved */
size_t static cellophane_write_callback_func(void *buffer,
                        size_t size,
                        size_t nmemb,
                        void *userp)
{
    char **response_ptr =  (char**)userp;

    /* assuming the response is a string */
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));

}

char** cellophane_str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}


int cellophane_number_of_message(char * buffer, int n){

        int msg_counter = 0;
        int buffer_pointer = 0;

        while(buffer_pointer < n){

            int payload_len = (int)(buffer[buffer_pointer]);
            buffer_pointer++;
            switch (payload_len) {
                case 126:
                    {
                        char aux_len [2];
                        strncpy(aux_len, buffer+buffer_pointer,2);
                        payload_len = (((int)aux_len[0] & 0x00FF) << 8) | (aux_len[1]  & 0x00FF);
                        buffer_pointer = buffer_pointer + 2;
                        break;
                    }
                case 127:
                    //perror("Next 8 bytes are 64bit uint payload length, not yet implemented, since PHP can't handle 64bit longs!");
                    break;
            }

            if((n-buffer_pointer)< payload_len){

                return -1;
            }

            buffer_pointer = buffer_pointer + payload_len +1;
            msg_counter++;
        }
        return msg_counter;
}

int cellophane_find_on_char_array(char ** tokens , char * key){

    if (tokens)
    {
        int i;
        for (i = 0; *(tokens + i); i++)
        {
            if(strcmp(*(tokens + i), key) == 0){
                return 1;
            }
        }
    }

    return 0;

}

void cellophane_compute_md5(char *str, unsigned char digest[16]) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, str, strlen(str));
    MD5_Final(digest, &ctx);
}

static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char *encoded, const char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
                    ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                    ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
        *p++ = basis_64[((string[i] & 0x3) << 4)];
        *p++ = '=';
    }
    else {
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}
