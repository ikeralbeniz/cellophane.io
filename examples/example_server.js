/*
 * Example of a node.Js socket.io server.
 *
 */


var app = require('http').createServer(handler),
  io = require('socket.io').listen(app),
  url=require('url');

// creating the server ( localhost:8000 ) 
app.listen(8000);

var devices_conected = new Array(); 

// on server started we can load our client.html page
function handler(req, res) {
  res.writeHead(200);
  res.end("");
}

// creating a new websocket to keep the content updated without any AJAX request
io.sockets.on('connection', function(socket) {


  socket.on('login', function (data) {
        console.log(data);
        socket.volatile.emit('notification', "test");
  });


});