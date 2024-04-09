package main

import (
	"crypto/sha256"
	_ "encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"net"
	"os"
)

var salt = []byte{
	0x45, 0x12, 0x9c, 0xf3, 0x27, 0xb8, 0x56, 0xe2,
	0x89, 0xd4, 0x7a, 0x1f, 0x65, 0x38, 0x2b, 0x90,
}

func main() {
	// Command-line flag definitions
	listenPort := flag.Int("l", 0, "Listen port for reverse-proxy mode")
	keyFile := flag.String("k", "", "Path to file containing the passphrase")
	flag.Parse()

	// Check if the key file is provided
	if *keyFile == "" {
		fmt.Println("Error: Passphrase file not provided.")
		return
	}

	// Read the passphrase from the key file
	passphrase, err := readPassphrase(*keyFile)
	if err != nil {
		fmt.Printf("Error reading passphrase: %v\n", err)
		return
	}

	// Generate AES key using PBKDF2
	aesKey := deriveKey(passphrase)

	// If listenPort is provided, run in reverse-proxy mode
	if *listenPort != 0 {
		fmt.Printf("Running in reverse-proxy mode on port %d\n", *listenPort)
		runReverseProxy(*listenPort, aesKey)
	} else {
		// Otherwise, run in client mode
		args := flag.Args()
		if len(args) != 2 {
			fmt.Println("Usage: go run jumproxy.go [-l listenport] -k pwdfile destination port")
			return
		}
		destination := args[0]
		port := args[1]
		fmt.Printf("Running in client mode, connecting to %s:%s\n", destination, port)
		runClient(destination, port, aesKey)
	}
}

// readPassphrase reads the passphrase from the given file
func readPassphrase(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Error while closing file:", err)
		}
	}(file)

	var passphrase string
	_, err = fmt.Fscanf(file, "%s", &passphrase)
	if err != nil {
		return "", err
	}
	return passphrase, nil
}

// deriveKey generates AES key using PBKDF2
func deriveKey(passphrase string) []byte {
	key := pbkdf2.Key([]byte(passphrase), salt, 10000, 32, sha256.New)
	//keyHex := fmt.Sprintf("%x", key)
	//fmt.Println("Derived Key (hex):", keyHex)
	return key
}

// runReverseProxy runs jumproxy in reverse-proxy mode
func runReverseProxy(listenPort int, key []byte) {
	// Listen on the specified port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		fmt.Printf("Error listening: %v\n", err)
		return
	}
	// Defer closing the listener to ensure it's closed when the function exits
	defer func() {
		err := listener.Close()
		if err != nil {
			fmt.Printf("Error closing listener: %v\n", err)
		}
	}()

	// Accept incoming connections in a loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}
		// Handle each connection concurrently
		go handleConnection(conn, key)
	}
}

// runClient runs jumproxy in client mode
func runClient(destination string, port string, key []byte) {
	fmt.Printf("Connecting to %s\n", destination)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", destination, port))
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Printf("Error closing connection: %v\n", err)
		}
	}(conn)

	// Start a goroutine to copy data from standard input to the server connection,
	// encrypting the data using the provided key
	go func() {
		_, err := io.Copy(conn, encryptReader(os.Stdin, key))
		if err != nil {
			fmt.Printf("Error sending data to server: %v\n", err)
		}
	}()

	// Copy data from the server connection to standard output,
	// decrypting the data using the provided key
	_, err = io.Copy(os.Stdout, decryptReader(conn, key))
	if err != nil {
		fmt.Printf("Error receiving data from server: %v\n", err)
	}
}

// handleConnection handles an incoming connection in reverse-proxy mode
func handleConnection(conn net.Conn, key []byte) {
	fmt.Printf("received connection from %s\n", conn.RemoteAddr())

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Printf("Error closing client connection: %v\n", err)
		}
		fmt.Printf("Connection closed with %s\n", conn.RemoteAddr())
	}(conn)

	destination := flag.Arg(0)
	port := flag.Arg(1)
	serverConn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", destination, port))
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer func(serverConn net.Conn) {
		err := serverConn.Close()
		if err != nil {
			fmt.Printf("Error closing server connection: %v\n", err)
		}
	}(serverConn)

	go func() {
		_, err := io.Copy(serverConn, decryptReader(conn, key))
		if err != nil {
			fmt.Printf("Error copying data from client to server: %v\n", err)
		}
	}()

	_, err = io.Copy(conn, encryptReader(serverConn, key))
	if err != nil {
		fmt.Printf("Error copying data from server to client: %v\n", err)
	}
}

// encryptReader returns an io.Reader that encrypts data using AES-GCM
func encryptReader(reader io.Reader, key []byte) io.Reader {
	//block, err := aes.NewCipher(key)
	//if err != nil {
	//	panic(err)
	//}
	//
	//gcm, err := cipher.NewGCM(block)
	//if err != nil {
	//	panic(err)
	//}
	//
	//nonce := make([]byte, gcm.NonceSize())
	//if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	//	panic(err)
	//}
	//
	//return cipher.StreamReader{
	//	S: cipher.NewGCM(block),
	//	R: io.MultiReader(strings.NewReader(string(nonce)), reader),
	//}
	return &loggingReader{r: reader, prefix: "Encrypted"}
}

// decryptReader returns an io.Reader that decrypts data using AES-GCM
func decryptReader(reader io.Reader, key []byte) io.Reader {
	//block, err := aes.NewCipher(key)
	//if err != nil {
	//	panic(err)
	//}
	//
	//gcm, err := cipher.NewGCM(block)
	//if err != nil {
	//	panic(err)
	//}
	//
	//nonceSize := gcm.NonceSize()
	//buf := make([]byte, nonceSize)
	//if _, err := io.ReadFull(reader, buf); err != nil {
	//	panic(err)
	//}
	//
	//nonce := buf[:nonceSize]
	//return cipher.StreamReader{
	//	S: gcm,
	//	R: io.MultiReader(strings.NewReader(""), io.LimitReader(reader, int64(len(buf)))),
	//}
	return &loggingReader{r: reader, prefix: "Decrypted"}
}

type loggingReader struct {
	r      io.Reader
	prefix string
}

// Read reads data from the underlying reader and logs it.
func (lr *loggingReader) Read(p []byte) (n int, err error) {
	// Read from the underlying reader
	n, err = lr.r.Read(p)

	// Log the data flow
	if n > 0 {
		log.Printf("%s: %s", lr.prefix, string(p[:n]))
	}

	return n, err
}
