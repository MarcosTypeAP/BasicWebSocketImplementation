# BasicWebSocketImplementation

A basic C implementation of the WebSocket protocol following the [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455). You can only receive data and print it to stdout.

# Usage

### Compile

```bash
gcc ws_server.c -lcrypto -o out
```

Now run it with `./out`.

### Client

Connect to the server through the browser or whatever technology you want to use.

```javascript
const ws = new WebSocket('ws://127.0.0.1:8080')
ws.onopen = () => console.log('Connected')

ws.send('Test message')
```

And you will see `Test Message` in the program output.
