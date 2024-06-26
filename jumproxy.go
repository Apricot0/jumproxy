package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	_ "encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

var salt = []byte{
	0x45, 0x12, 0x9c, 0xf3, 0x27, 0xb8, 0x56, 0xe2,
	0x89, 0xd4, 0x7a, 0x1f, 0x65, 0x38, 0x2b, 0x90,
}

var logFile *os.File

func init() {
	// Open or create the log file
	var err error
	logFile, err = os.OpenFile("logfile.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v", err)
	}

	// Set log output to the file
	log.SetOutput(logFile)
}

func main() {
	usage := `go run jumproxy.go [-l listenport] -k pwdfile destination port

  -l  Reverse-proxy mode: listen for inbound connections on <listenport> and
      relay them to <destination>:<port>

  -k  Use the ASCII text passphrase contained in <pwdfile>`
	defer func(logFile *os.File) {
		err := logFile.Close()
		if err != nil {

		}
	}(logFile)
	// define command-line
	listenPort := flag.Int("l", 0, "Listen port for reverse-proxy mode")
	keyFile := flag.String("k", "", "Path to file containing the passphrase")
	flag.Parse()

	// check the key file
	if *keyFile == "" {
		fmt.Printf("Error: Passphrase file not provided.\n%s\n", usage)
		return
	}

	// read the passphrase
	passphrase, err := readPassphrase(*keyFile)
	if err != nil {
		fmt.Printf("Error reading passphrase: %v\n", err)
		return
	}

	// generate AES key using PBKDF2
	aesKey := generateKey(passphrase)

	// if listenPort is provided, run in reverse-proxy mode
	if *listenPort != 0 {
		dest := flag.Arg(0)
		port := flag.Arg(1)
		fmt.Printf("Running in reverse-proxy mode on port %d\n", *listenPort)
		reverseProxy(*listenPort, aesKey, dest, port)
	} else {
		// Otherwise, run in client mode
		args := flag.Args()
		if len(args) != 2 {
			fmt.Printf("%s\n", usage)
			return
		}
		destination := args[0]
		port := args[1]
		fmt.Printf("Running in client mode, connecting to %s:%s\n", destination, port)
		client(destination, port, aesKey)
	}
}

// reads the passphrase from the given file
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

// generates AES key using PBKDF2
func generateKey(passphrase string) []byte {
	key := pbkdf2.Key([]byte(passphrase), salt, 10000, 32, sha256.New) //32 byte, 256 bits
	//keyHex := fmt.Sprintf("%x", key)
	//fmt.Println("Derived Key (hex):", keyHex)
	return key
}

// runs jumproxy in reverse-proxy mode
func reverseProxy(listenPort int, key []byte, dest string, port string) {
	// listen on the specified port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		log.Printf("Error listening: %v\n", err)
		return
	}
	// Defer closing the listener to ensure it's closed when the function exits
	defer func() {
		err := listener.Close()
		log.Printf("Listener closed.\n")
		if err != nil {
			log.Printf("Error closing listener: %v\n", err)
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
		go handleConnection(conn, dest, port, key)
	}
}

// client runs jumproxy in client mode
func client(destination string, port string, key []byte) {
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
		//_, err := io.Copy(conn, encryptReader(os.Stdin, key))
		err := encryptTransmission(os.Stdin, conn, key)
		if err != nil {
			fmt.Printf("Error sending data to server: %v\n", err)
		}
	}()

	// Copy data from the server connection to standard output,
	// decrypting the data using the provided key
	//_, err = io.Copy(os.Stdout, decryptReader(conn, key))
	err = decryptTransmission(conn, os.Stdout, key)
	if err != nil {
		fmt.Printf("Error receiving data from server: %v\n", err)
	}
}

// handleConnection handles an incoming connection in reverse-proxy mode
func handleConnection(conn net.Conn, dest string, port string, key []byte) {
	fmt.Printf("Received connection from %s\n", conn.RemoteAddr())
	log.Printf("Received connection from %s\n", conn.RemoteAddr())
	serverConn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", dest, port))
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		return
	}
	log.Printf("Successfully connected to %s\n", conn.RemoteAddr())
	defer func(serverConn net.Conn) {
		err := serverConn.Close()
		if err != nil {
			fmt.Printf("Error closing server connection: %v\n", err)
		}
		log.Printf("Connection closed with server: %s\n", serverConn.RemoteAddr())
	}(serverConn)

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Printf("Error closing client connection: %v\n", err)
		}
		fmt.Printf("Connection closed with client: %s\n", conn.RemoteAddr())
	}(conn)

	go func() {
		//_, err := io.Copy(serverConn, decryptReader(conn, key))
		err := decryptTransmission(conn, serverConn, key)
		if err != nil {
			log.Printf("Error copying data from client to server: %v\n", err)
		}
	}()

	//_, err = io.Copy(conn, encryptReader(serverConn, key))
	err = encryptTransmission(serverConn, conn, key)
	if err != nil {
		log.Printf("Error copying data from server to client: %v\n", err)
	}
}

func encryptTransmission(src io.Reader, dst io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM cipher: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		if err == io.EOF {
			// Handle EOF error
			log.Println("Nonce EOF reached. Ending decryption process.")
		}
		log.Printf("ET: Error reading nonce: %v", err)
	}

	// Write the nonce to the beginning of the stream
	if _, err := dst.Write(nonce); err != nil {
		log.Printf("ET: Error writing nonce: %v", err)
		return err
	}
	log.Printf("Starting encryption transmission...")
	buf := make([]byte, 2468)
	var content []byte

	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			log.Printf("ET: Error reading from %v: %v", buf, err)
			return err
		}
		if n == 0 {
			log.Printf("ET: Break because n=0")
			break
		}
		//log.Printf("Before Encrypted %s\n", string(buf[:n]))
		encrypted := gcm.Seal(nil, nonce, buf[:n], nil)
		//log.Printf("After Encrypted %d\n", encrypted)
		encryptedSize := make([]byte, 8) // Assuming 64-bit integer for size
		binary.BigEndian.PutUint64(encryptedSize, uint64(len(encrypted)))
		_, err = dst.Write(encryptedSize)
		if err != nil {
			log.Printf("ET: Error writing size")
			return err
		}
		_, err = dst.Write(encrypted)
		if err != nil {
			log.Printf("ET: Error writing %v: %v", buf, err)
			return err
		}
		log.Printf("ET:Reader --%d--> Writer", len(encrypted))

		content = append(content, buf[:n]...)
		if err == io.EOF {
			log.Printf("ET: EOF")
			break
		}
	}
	log.Printf("Encrypt transmission Complete Copied content: %d\n", len(content))
	return nil
}

func decryptTransmission(src io.Reader, dst io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM cipher: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(src, nonce); err != nil {
		if err == io.EOF {
			// Handle EOF error
			log.Println("Nonce EOF reached. Ending decryption process.")
		}
		log.Printf("DT: Error reading nonce: %v", err)
	}
	//log.Printf("Nonce: %d; Key: %d\n", nonce, key)
	log.Printf("Starting decryption transmission...")
	//buf := make([]byte, 2468)
	buf := make([]byte, 8)
	var content []byte

	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			log.Printf("DT: Error reading from %v: %v", buf, err)
			return err
		}
		if n == 0 {
			log.Printf("DT: Break because n = 0")
			break
		}
		encryptedSize := binary.BigEndian.Uint64(buf)
		encrypted := make([]byte, encryptedSize)
		_, err = io.ReadFull(src, encrypted)
		//log.Printf("Before Decrypted: %d\n", encrypted)
		decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
		//log.Printf("After Decrypted: %s\n", decrypted)
		if err != nil {
			log.Printf("DT: error")
			return err
		}
		_, err = dst.Write(decrypted)
		if err != nil {
			log.Printf("DT: write Error")
			return err
		}
		log.Printf("DT:Writer <--%d-- Reader", len(decrypted))

		content = append(content, buf[:n]...)
		if err == io.EOF {
			log.Printf("DT: EOF")
			break
		}
	}
	log.Printf("Decrypt transmission complete Copied content: %d\n", len(content))
	return nil
}

//// encryptReader returns an io.Reader that encrypts data using AES-GCM
//func encryptReader(reader io.Reader, key []byte) io.Reader {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		log.Fatalf("Error creating AES cipher: %v", err)
//	}
//
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		log.Fatalf("Error creating GCM cipher: %v", err)
//	}
//
//	nonce := make([]byte, gcm.NonceSize())
//	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
//		log.Fatalf("Error generating nonce: %v", err)
//	}
//
//	log.Printf("Encrypt using nonce: %d , key: %d", nonce, key)
//	// Encrypt data as it's read from the input stream
//	pr, pw := io.Pipe()
//
//	go func() {
//		buf := make([]byte, 8192) // Adjust buffer size as needed
//		for {
//			n, err := reader.Read(buf)
//			if err != nil && err != io.EOF {
//				log.Fatalf("Error reading input: %v", err)
//			}
//			if n == 0 {
//				break
//			}
//
//			// Log the content of buf
//			log.Printf("Encrypt Buffer content: %s", buf[:n])
//			encrypted := gcm.Seal(nonce, nonce, buf[:n], nil)
//			log.Printf("After encrypt content: %d", encrypted)
//			if _, err := pw.Write(encrypted); err != nil {
//				log.Fatalf("Error writing encrypted data: %v", err)
//			}
//		}
//		pw.Close()
//	}()
//
//	return pr
//	//return &loggingReader{r: reader, prefix: "Encrypted"}
//}
//
//// decryptReader returns an io.Reader that decrypts data using AES-GCM
//func decryptReader(reader io.Reader, key []byte) io.Reader {
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		log.Fatalf("Error creating AES cipher: %v", err)
//	}
//
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		log.Fatalf("Error creating GCM cipher: %v", err)
//	}
//
//	nonceSize := gcm.NonceSize()
//
//	pr, pw := io.Pipe()
//
//	go func() {
//		buf := make([]byte, 8192) // Adjust buffer size as needed
//		for {
//			nonceBuf := make([]byte, nonceSize)
//			if _, err := io.ReadFull(reader, nonceBuf); err != nil {
//				if err == io.EOF {
//					// Handle EOF error
//					log.Println("Nonce EOF reached. Ending decryption process.")
//					return
//				}
//				log.Printf("Error reading nonce: %v", err)
//				continue
//			}
//			nonce := nonceBuf[:nonceSize]
//			log.Printf("Decrypt using nonce: %d , key: %d", nonce, key)
//			n, err := reader.Read(buf)
//			if err != nil && err != io.EOF {
//				pw.CloseWithError(err)
//				return
//			}
//			if n == 0 {
//				break
//			}
//			log.Printf("Before decrypt content: %d", buf[:n])
//			decrypted, err := gcm.Open(nil, nonce, buf[:n], nil)
//			if err != nil {
//				pw.CloseWithError(errors.New("decryption error: " + err.Error()))
//				return
//			}
//
//			if _, err := pw.Write(decrypted); err != nil {
//				pw.CloseWithError(err)
//				return
//			}
//			log.Printf("Decrypted content: %s\n", decrypted)
//		}
//		pw.Close()
//	}()
//
//	return pr
//	//return &loggingReader{r: reader, prefix: "Encrypted"}
//}

//type loggingReader struct {
//	r      io.Reader
//	prefix string
//}
//
//// Read reads data from the underlying reader and logs it.
//func (lr *loggingReader) Read(p []byte) (n int, err error) {
//	// Read from the underlying reader
//	n, err = lr.r.Read(p)
//
//	// Log the data flow
//	if n > 0 {
//		log.Printf("%s: %s", lr.prefix, string(p[:n]))
//	}
//
//	return n, err
//}
