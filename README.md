# babyl

A terminal-based P2P encrypted chat app.

Babyl uses Elliptic Curve Diffie-Hellman Exchange to allow peers to coordinate a shared secret amongst themselves. This secret is then used to generate an AES-128 symmetric key under the CBC mode of operation. This symmetric key is used to encrypt and decrypt chat messages, and HMAC-SHA1 (I know, SHA1...) is used to authentication incoming messages.

![Babyl Example GIF](https://raw.githubusercontent.com/aunyks/babyl/master/babyl-demo.gif)

## Get Started

Assuming you have the repository cloned into your Go workspace:

```
> go get -u && go build
```

## Usage

```
> babyl -help
A terminal-based P2P encrypted chat app.

Usage: Run 'babyl -sp <SOURCE_PORT>' where <SOURCE_PORT> can be any port number.
Now run 'babyl -d <MULTIADDR>' where <MULTIADDR> is multiaddress of previous listener host.
```

---

Copyright (c) 2018 Gerald Nash
