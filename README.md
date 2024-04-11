# jumproxy
## File Structure:
```
|--LICENSE
|--README.md
|--go.mod
|--go.sum
|--jumproxy.go
|--pwdfile
```


## Overview
`jumproxy` help you add an extra layer
of protection to publicly accessible TCP services

Consider for example the case of an SSH server with a public IP address. No
matter how securely the server has been configured and how strong the keys
used are, it might suffer from a "pre-auth" zero day vulnerability that allows
remote code execution even before the completion of the authentication
process. This could allow attackers to compromise the server even without
providing proper authentication credentials.

The `jumproxy`, adds an extra layer
of encryption to connections towards TCP services. Instead of connecting
directly to the service, clients connect to `jumproxy` (running on the same
server that hosts the service), which then relays all traffic to the actual
service. Before relaying the traffic, `jumproxy` always decrypts it using a
static symmetric key. This means that if the data of any connection towards
the protected server is not properly encrypted, then the server will terminate
the connection. Clients who want to access the protected service should proxy their traffic
through a local instance of `jumproxy`, which will encrypt the traffic using the
same symmetric key used by the server. In essence, jumproxy acts both as a
client-side proxy (when the `-l` option is not provided) and as server-side
reverse proxy (when the `-l` option is provided), in a way similar to `netcat`.

Data is encrypted/decrypted using AES-256 in GCM mode in both
directions. `jumproxy` derive an appropriate AES key from the supplied
passphrase using PBKDF2.


## Install
If you simply want to run proxy inside the project directory, then build it by 
running `go builld` inside the project root directory. If you want to install 
the project globally on your system, you can use `go install` after building the project. 

## Usage
```
go run jumproxy.go [-l listenport] -k pwdfile destination port

  -l  Reverse-proxy mode: listen for inbound connections on <listenport> and
      relay them to <destination>:<port>

  -k  Use the ASCII text passphrase contained in <pwdfile>
```
or if you have already build the `jumproxy`:
```
./jumproxy [-l listenport] -k pwdfile destination port

  -l  Reverse-proxy mode: listen for inbound connections on <listenport> and
      relay them to <destination>:<port>

  -k  Use the ASCII text passphrase contained in <pwdfile>
```
## Examples
Assume that we want to protect a publicly accessible sshd
running on 192.168.19.129. First, we should configure sshd to listen *only* on
the localhost interface, making it inaccessible from the network. Then, we
fire up a reverse jumproxy instance on the same host, listening on port 2222,
and forwarding all traffic to localhost:22

Server:
```
./jumproxy -k pwdfile -l 2222 localhost 22
```
Clients can then connect to the SSH server using the following command:
```
ssh -o "ProxyCommand ./jumproxy -k pwdfile 192.168.19.129 2222" kali@192.168.19.129
```

## Data Flow
```
ssh <--stdin/stdout--> jumproxy <--socket 1--> jumproxy <--socket 2--> sshd
\_____________________________/                \__________________________/
             client                                       server           
```
## Implementation
The `main` function reads the flags and determines whether `jumproxy` should run in 
client mode or reverse-proxy mode and reads the necessary passphrase, destination 
port, and destination address. It then utilizes PBKDF2 from `golang.org/x/crypto/pbkdf2`
and the passphrase to generate the ACM key. If it runs in reverse-proxy mode, it uses the
built-in package `net` to listen on the specified port. Upon receiving a connection from 
that port, a new thread is created to handle transmission and dial the port to relay. 
Each transmission involves two-way encryption and decryption of data flows, handled 
separately and concurrently by `encryptTransmission` and `decryptTransmission`.

Both encryptTransmission and decryptTransmission operate similarly, utilizing a buffer 
inside a loop to continuously read content from the reader, encrypt it using `gcm.Seal`, 
and send it until reaching EOF. The data size within each buffer is also transmitted so
that `decryptTransmission` can determine the amount of data to decrypt using `gcm.Open` 
accordingly. The decrypted message is then sent to the writer, establishing a two-way 
connection on the server side. On the client side, the process is simpler. `jumproxy` does
not need to listen on any port. Instead, it utilizes the same `encryptTransmission` and
`decryptTransmission`, with the reader being stdin and stdout being the writer.
