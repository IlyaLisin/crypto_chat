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
    tcpProtocol	= "tcp4"
    keySize = 1024
    readWriterSize = keySize/8
)

func checkErr(err error){
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}

var connectAddr = &net.TCPAddr{IP: net.IPv4(127,0,0,1), Port: 0}

func connectTo() *net.TCPConn{
    fmt.Print("Enter port:")
    fmt.Scanf("%d", &connectAddr.Port)
    fmt.Println("Connect to", connectAddr)

    c ,err := net.DialTCP(tcpProtocol, nil, connectAddr); checkErr(err)
    return c
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

// Читает и освобождает определённый кусок буфера
func getBytes(buf *bufio.Reader, n int) []byte {
    // Читаем n байт
    bytes, err:= buf.Peek(n); checkErr(err)
    // Освобождаем n байт
    skipBytes(buf, n)
    return bytes
}

func skipBytes(buf *bufio.Reader, skipCount int){
    for i:=0; i<skipCount; i++ {
        buf.ReadByte()
    }
}

func waitPubKey(buf *bufio.Reader) (*rsa.PublicKey) {
    line, _, err := buf.ReadLine(); checkErr(err)

    if string(line) == "CONNECT" {

        // Далее мы будем читать буфер в том же порядке, в котором отправляем данные с клиента
        line, _, err := buf.ReadLine(); checkErr(err) // Читаем PublicKey.N

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

func main() {
    c := connectTo()

    // Буферизирует всё что приходит от соединения "c"
    buf := bufio.NewReader(c)

    k, err := rsa.GenerateKey(rand.Reader, keySize); checkErr(err)

    // Отправляем серверу публичный ключ
    sendKey(c, k)
    fmt.Println("Sended key by client")

    pubKey := waitPubKey(buf)

    // В цикле принимаем зашифрованные сообщения от сервера
    for {
        reader := bufio.NewReader(os.Stdin)
        fmt.Print("Text to send: ")
        text, _ := reader.ReadString('\n')
        eComm, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, []byte(text), nil); checkErr(err)
        _, err = c.Write(eComm); checkErr(err)

        // Получаем зашифрованное сообщение в байтах
        cryptMsg := getBytes(buf, readWriterSize)

        msg, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, k, cryptMsg, nil); checkErr(err)

        fmt.Println(string(msg))
    }
}
