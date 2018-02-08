# sslhash

SSL without a certificate authority.

## Why?

Have you ever wanted to use TLS over non-http TCP streams?  
If yes you'll realize it's quite complicated to set up certificates.  
Not all IPs even have domains!

sslhash basically skips the hostname check and instead compares it to a user-supplied hash of the public key.  
This takes the good of SSL (Security, audited, etc) and removes the bad of SSL (certificate authorities).

## Usage

Server:

```Rust
// Create a builder.
// Default values:
// - RSA bits: 3072
// - Cache directory: The same directory as the executable
let (acceptor, hash) = AcceptorBuilder::default().build().unwrap();

// Replace "localhost:1234" with what you want to bind to.
// On UNIX, use 0.0.0.0 as IP to make it public.
let tcp = TcpListener::bind("localhost:1234").unwrap();
let (client, _) = tcp.accept().unwrap();
let mut client = acceptor.accept(client).unwrap();

// client is a SslStream<TcpStream> now ready to be used.
// Somehow transfer the hash to the client.
// A simple way would be to tell the user to give this to all clients.
```

Client:

```Rust
let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

// Replace "localhost:1234" with what you want to connect to.
let client = TcpStream::connect("localhost:1234").unwrap();

// Assumes you have a String called "hash" that is the hash of the server's public key.
// Somehow receive this from the server.
// A simple way would be to ask the user for the hash.
let mut client = sslhash::connect(&connector, client, hash).unwrap();
```
