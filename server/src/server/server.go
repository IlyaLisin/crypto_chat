package main

import(
  "fmt"
  "net"
  "os"
  "bufio"
  "crypto/rsa"
  "crypto/rand"
  "crypto/sha1"
  "strconv"
  "math/big"
)

const(
  tcpProtocol = "tcp4"
  keySize = 1024
)

type remoteConn struct {
  c *net.TCPConn
  pubK *rsa.PublicKey
}

func checkErr(err error){
  if err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
}

var listenAddr = &net.TCPAddr{IP: net.IPv4(127,0,0,1), Port: 0}

func getRemoteConn(c *net.TCPConn) *remoteConn{
  return &remoteConn{c: c, pubK: waitPubKey(bufio.NewReader(c))}
}

func waitPubKey(buf *bufio.Reader) (*rsa.PublicKey) {
  line, _, err := buf.ReadLine(); checkErr(err)

  if string(line) == "CONNECT" {

    // Далее мы будем читать буфер в том же порядке, в котором отправляем данные с клиента
    line, _, err := buf.ReadLine(); checkErr(err) // Читаем PublicKey.N

    // Создаём пустой rsa.PublicKey
    pubKey := rsa.PublicKey{N: big.NewInt(0)}
    pubKey.N.SetString(string(line), 10)

    // Читаем из буфера второе число для pubKey.E
    line, _, err = buf.ReadLine(); checkErr(err)

    pubKey.E, err = strconv.Atoi(string(line)); checkErr(err)

    fmt.Println("Received public key from client")

    return &pubKey

  } else {

    fmt.Println("Error: unkown command ", string(line))
    os.Exit(1)
  }
  return nil
}

func (rConn *remoteConn) sendCommand(comm string) {
  eComm, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rConn.pubK, []byte(comm), nil); checkErr(err)

  rConn.c.Write(eComm)
}

// Функция в определённом порядке отправляет PublicKey
func sendKey(c *net.TCPConn, k *rsa.PrivateKey) {

  // Говорим серверу что сейчас будет передан PublicKey
  c.Write([]byte("CONNECT\n"))

  // передаём N типа *big.Int
  c.Write([]byte(k.PublicKey.N.String() + "\n"))

  // передаём E типа int
  c.Write([]byte(strconv.Itoa(k.PublicKey.E) + "\n"))
}

func getBytes(buf *bufio.Reader, n int) []byte {
  bytes, err:= buf.Peek(n); checkErr(err)
  skipBytes(buf, n)
  return bytes
}

// Освобождает, пропускает определённое количество байт
func skipBytes(buf *bufio.Reader, skipCount int){
  for i:=0; i<skipCount; i++ {
    buf.ReadByte()
  }
}

func listen() {
  // Слушаем любой свободны порт
  l, err := net.ListenTCP(tcpProtocol, listenAddr); checkErr(err)

  fmt.Println("Listen port: ", l.Addr().(*net.TCPAddr).Port)

  c, err := l.AcceptTCP(); checkErr(err)

  fmt.Println("Connect from:", c.RemoteAddr())

  // получим соединение и ключ которым можно зашифровать это соединение
  rConn := getRemoteConn(c)

  k, err := rsa.GenerateKey(rand.Reader, keySize); checkErr(err)
  sendKey(rConn.c, k)
  fmt.Println("Sended key by server")

  for {
    buf := bufio.NewReader(rConn.c)
    msg, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, k, getBytes(buf, 128), nil); checkErr(err)
    fmt.Println("Recieved", string(msg))
    rConn.sendCommand("Meesage from server: Accepted message: " + string(msg))
  }
}

func main() {
  listen()
}
