# ChatSec

ChatSec is an instant messaging and file transfer program written in Python. It uses a central server that acts as a
central authority, which allows the clients to communicate with each other directly. The authentication and communication
is encrypted using AES.

This is a networking project for the Network and Internetwork Security course at the University of Cape Town.

## Requirements

[PyCrypto](https://www.dlitz.net/software/pycrypto/)

[pytest](http://pytest.org/latest/)

## Use

In order to use this demo, start the server script and then start the client scripts (cli[1-3].py). To enable logging of information 
for the client scripts, change the line "logging.basicConfig(stream=sys.stderr, level=logging.CRITICAL)" to 
"logging.basicConfig(stream=sys.stderr, level=logging.INFO)" in the client.py file.

Once two or more clients are connected, select the ID of the other client from one and commence chatting.

## Links

[sockets](https://docs.python.org/2/howto/sockets.html)

## License

Pfeh, who needs one of these?