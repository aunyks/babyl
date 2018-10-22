package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-crypto"
	"github.com/libp2p/go-libp2p-host"
	"github.com/libp2p/go-libp2p-net"
	"github.com/libp2p/go-libp2p-peer"
	"github.com/libp2p/go-libp2p-peerstore"
	"github.com/multiformats/go-multiaddr"
)

func addAddrToPeerstore(h host.Host, addr string) peer.ID {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		log.Fatalln(err)
	}
	info, err := peerstore.InfoFromP2pAddr(maddr)
	if err != nil {
		log.Fatalln(err)
	}
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
	return info.ID
}

func handleStream(s net.Stream) {
	log.Println("New chat connection!")
	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	sessionPrivKey, err := ecdsa.GenerateKey(Curve(), rand.Reader)
	if err != nil {
		os.Exit(1)
	}
	sessionPubKey := sessionPrivKey.PublicKey
	serialPubKey := append(sessionPubKey.X.Bytes(), sessionPrivKey.Y.Bytes()...)
	serialPeerPubKey, _ := rw.ReadString('\n')
	rw.WriteString(base64.StdEncoding.EncodeToString(serialPubKey) + "\n")
	rw.Flush()
	bytesPeerPubKey, err := base64.StdEncoding.DecodeString(serialPeerPubKey)
	if err != nil {
		os.Exit(1)
	}
	peerXBytes := bytesPeerPubKey[:32]
	peerYBytes := bytesPeerPubKey[32:]
	peerX := new(big.Int)
	peerX.SetBytes(peerXBytes)
	peerY := new(big.Int)
	peerY.SetBytes(peerYBytes)
	peerPublicKey := ecdsa.PublicKey{
		Curve: Curve(),
		X:     peerX,
		Y:     peerY,
	}
	go readData(rw, sessionPrivKey)
	go writeData(rw, &peerPublicKey, sessionPrivKey)
}

func readData(rw *bufio.ReadWriter, privKey *ecdsa.PrivateKey) {
	for {
		rawStr, _ := rw.ReadString('\n')
		decodedStr, err := base64.StdEncoding.DecodeString(rawStr)
		if err != nil {
			os.Exit(1)
		}
		decryptedStr, err := Decrypt(privKey, decodedStr)
		str := string(decryptedStr)
		if str == "" || err != nil {
			os.Exit(1)
		}
		if str != "\n" {
			// Green console colour: 	\x1b[32m
			// Reset console colour: 	\x1b[0m
			if strings.TrimSpace(str) != "exit" {
				fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
			} else {
				fmt.Println("Peer exited chat!")
				os.Exit(0)
			}
		}
	}
}

func writeData(rw *bufio.ReadWriter, pubKey *ecdsa.PublicKey, privKey *ecdsa.PrivateKey) {
	stdReader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		stdData, err := stdReader.ReadString('\n')
		if err != nil {
			os.Exit(1)
		}
		sendData, err := Encrypt(pubKey, privKey, []byte(stdData))
		if err != nil {
			os.Exit(1)
		}
		rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(sendData)))
		rw.Flush()
	}

}

func main() {
	sourcePort := flag.Int("sp", 0, "Source port number")
	dest := flag.String("d", "", "Destination multiaddr string")
	help := flag.Bool("help", false, "Display help")
	debug := flag.Bool("debug", false, "Debug generates the same node ID on every execution")
	flag.Parse()
	if *help {
		fmt.Printf("A terminal-based P2P encrypted chat app.\n\n")
		fmt.Println("Usage: Run 'babyl -sp <SOURCE_PORT>' where <SOURCE_PORT> can be any port number.")
		fmt.Println("Now run 'babyl -d <MULTIADDR>' where <MULTIADDR> is multiaddress of previous listener host.")
		os.Exit(0)
	}

	var r io.Reader
	if *debug {
		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
	} else {
		r = rand.Reader
	}

	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		os.Exit(1)
	}
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *sourcePort))
	host, err := libp2p.New(
		context.Background(),
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
	)
	if err != nil {
		os.Exit(1)
	}

	if *dest == "" {
		host.SetStreamHandler("/chat/1.0.0", handleStream)
		var port string
		for _, la := range host.Network().ListenAddresses() {
			if p, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
				port = p
				break
			}
		}
		if port == "" {
			panic("Unable to find actual local port")
		}
		fmt.Printf("Run 'babyl -d /ip4/127.0.0.1/tcp/%v/p2p/%s' in another console.\n", port, host.ID().Pretty())
		fmt.Println("You can replace 127.0.0.1 with public IP address as well.")
		fmt.Printf("\nWaiting for incoming connection\n\n")
		<-make(chan struct{})
	} else {
		fmt.Println("This node's multiaddresses:")
		for _, la := range host.Addrs() {
			fmt.Printf(" - %v\n", la)
		}
		fmt.Println()
		maddr, err := multiaddr.NewMultiaddr(*dest)
		if err != nil {
			log.Fatalln(err)
		}
		info, err := peerstore.InfoFromP2pAddr(maddr)
		if err != nil {
			log.Fatalln(err)
		}

		host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
		s, err := host.NewStream(context.Background(), info.ID, "/chat/1.0.0")
		if err != nil {
			os.Exit(1)
		}

		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
		sessionPrivKey, err := ecdsa.GenerateKey(Curve(), rand.Reader)
		if err != nil {
			os.Exit(1)
		}
		sessionPubKey := sessionPrivKey.PublicKey
		serialPubKey := append(sessionPubKey.X.Bytes(), sessionPrivKey.Y.Bytes()...)
		rw.WriteString(base64.StdEncoding.EncodeToString(serialPubKey) + "\n")
		rw.Flush()
		serialPeerPubKey, _ := rw.ReadString('\n')
		bytesPeerPubKey, err := base64.StdEncoding.DecodeString(serialPeerPubKey)
		if err != nil {
			os.Exit(1)
		}
		peerXBytes := bytesPeerPubKey[:32]
		peerYBytes := bytesPeerPubKey[32:]
		peerX := new(big.Int)
		peerX.SetBytes(peerXBytes)
		peerY := new(big.Int)
		peerY.SetBytes(peerYBytes)
		peerPublicKey := ecdsa.PublicKey{
			Curve: Curve(),
			X:     peerX,
			Y:     peerY,
		}
		go readData(rw, sessionPrivKey)
		go writeData(rw, &peerPublicKey, sessionPrivKey)
		select {}
	}
}
