/*
 * Example of a socket.io client.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <cellophaneio/cellophane_io.h>

void on_notofication_callback(char * data){

    printf("Notification: %s\n", data);
}

int main()
{

    WsHandler io_client;
    cellophane_io(&io_client,"http://", "localhost", 8000);
    cellophane_emit(&io_client,"login", "foo","");
    cellophane_on(&io_client,"notofication", on_notofication_callback);
    cellophane_keepAlive(&io_client);
    cellophane_close(&io_client);
    return 0;
}