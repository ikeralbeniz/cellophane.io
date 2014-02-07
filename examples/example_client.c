/*
 * Example of a socket.io client.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <cellophaneio/cellophane_io.h>

void on_notofication_callback(WsEventInfo info){

    WsHandler * parent_client = (WsHandler *) info.ws_handler;
    printf("Notification: %s\n", info.message);

}

int main()
{

    WsHandler io_client;
    cellophane_io(&io_client,"http://", "localhost", 8000);

    cellophane_set_debug(&io_client, DEBUG_DETAILED);
    cellophane_on(&io_client, "anything", on_notofication_callback);

    cellophane_io_connect(&io_client);
    cellophane_emit(&io_client,"login", "foo","");
    cellophane_keepAlive(&io_client);

    cellophane_close(&io_client);
    return 0;

}
