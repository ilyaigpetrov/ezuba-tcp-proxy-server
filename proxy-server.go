package main

import (
  "io"
  //"io/ioutil"
  "net"
  "sync"
  "fmt"
  "flag"
  "strings"
  "bytes"
  "golang.org/x/net/ipv4"
  "encoding/hex"
  "os"
  "os/signal"
  "errors"
  "syscall"

  log "github.com/Sirupsen/logrus"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

func xor42(data []byte) []byte {
  for i, b := range data {
    data[i] = b ^ 42
  }
  return data
}

var connection net.Conn

type Proxy struct {
  from string
  fromTCP *net.TCPAddr
  done chan struct{}
  log  *log.Entry
}

func NewProxy(from string) *Proxy {

  log.SetLevel(log.InfoLevel)
  return &Proxy{
    from: from,
    done: make(chan struct{}),
    log: log.WithFields(log.Fields{
      "from": from,
    }),
  }

}

func (p *Proxy) Start() error {
  p.log.Infoln("Starting proxy")
  var err error
  p.fromTCP, err = net.ResolveTCPAddr("tcp", p.from)
  if (err != nil) {
    panic(err)
  }
  listener, err := net.ListenTCP("tcp", p.fromTCP)
  if err != nil {
    return err
  }
  go p.run(*listener)
  return nil
}

func (p *Proxy) Stop() {
  p.log.Infoln("Stopping proxy")
  if p.done == nil {
    return
  }
  close(p.done)
  p.done = nil
}


func (p *Proxy) run(listener net.TCPListener) {
  for {
    select {
    case <-p.done:
      return
    default:
      var err error
      connection, err = listener.Accept()
      if connection == nil {
        p.log.WithField("err", err).Errorln("Nil connection")
        panic(err)
      }
      la := connection.LocalAddr()
      if (la == nil) {
        panic("Connection lost!")
      }
      fmt.Printf("Connection from %s\n", la.String())

      if err == nil {
        go p.handle(connection)
      } else {
        p.log.WithField("err", err).Errorln("Error accepting conn")
      }
    }
  }
}

func isLocalIP(ip string) bool {
    if strings.HasPrefix(ip, "127.") || ip == "0.0.0.0" {
      return true
    }
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return false
    }
    for _, address := range addrs {
        // check the address type and if it is not a loopback the display it
        if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
              if ip == ipnet.IP.String() {
                return true
              }
            }
        }
    }
    return false
}

func GetOutboundIP() net.IP {

  conn, err := net.Dial("udp", "8.8.8.8:80")
  if err != nil {
      log.Fatal(err)
  }
  defer conn.Close()

  localAddr := conn.LocalAddr().(*net.UDPAddr)

  return localAddr.IP

}

var myOutboundIP = GetOutboundIP()
var srcToIPConn = make(map[string]*net.IPConn)

func handleRepliesFromIPConn(ipconn *net.IPConn, originalIP net.IP, originalPort layers.TCPPort, src string) {

  defer ipconn.Close()
  defer delete(srcToIPConn, src)
  for {
    packetData := make([]byte, 65535)
    ipconn.ReadMsgIP(packetData, []byte{})

    _, ip, tcp, recompilePacket, err := parseTCPPacket(packetData)
    if err != nil {
      fmt.Println(err)
      break
    }

    ip.DstIP = originalIP
    tcp.DstPort = originalPort
    modPacket, err := recompilePacket()
    if err != nil {
      fmt.Println(err)
      break
    }
    fmt.Println("Sending:")
    fmt.Println(hex.EncodeToString(modPacket))

    _, err = io.Copy(connection, bytes.NewReader(xor42(modPacket)))
    if err != nil {
      fmt.Println(err)
      break
    }
  }

}

func parseTCPPacket(packetData []byte) (packet gopacket.Packet, ip *layers.IPv4, tcp *layers.TCP, recompilePacket func() ([]byte, error), err error) {

  packet = gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

  ipLayer := packet.Layer(layers.LayerTypeIPv4)
  if ipLayer == nil {
    err = errors.New("No IP layer!")
    return
  }
  ip = ipLayer.(*layers.IPv4)

  tcpLayer := packet.Layer(layers.LayerTypeTCP)
  if tcpLayer == nil {
    err = errors.New("No TCP layer!")
    return
  }
  tcp = tcpLayer.(*layers.TCP)

  recompilePacket = func() ([]byte, error) {

    options := gopacket.SerializeOptions{
      ComputeChecksums: true,
      FixLengths: true,
    }
    newBuffer := gopacket.NewSerializeBuffer()
    tcp.SetNetworkLayerForChecksum(ip)
    err := gopacket.SerializePacket(newBuffer, options, packet)
    if err != nil {
      return nil, err
    }
    return newBuffer.Bytes(), nil

  }

  return

}

func sendViaSocket(packetData []byte, toIP net.IP) error {

  s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
  if err != nil {
    return err
  }
  defer syscall.Close(s)

  var arr [4]byte
  copy(arr[:], toIP.To4()[:4])
  addr := syscall.SockaddrInet4{
    Addr: arr,
  }
  return syscall.Sendto(s, packetData, 0, &addr)

}

func (p *Proxy) handle(conn net.Conn) {

  defer conn.Close()
  p.log.Debugln("Handling", conn)
  defer p.log.Debugln("Done handling", conn)

  buf := make([]byte, 0, 8186) // big buffer
  tmp := make([]byte, 4096)     // using small tmo buffer for demonstrating
  for {
    n, err := conn.Read(tmp)
    if err != nil {
      if err != io.EOF {
            fmt.Println("read error:", err)
        }
        break
    }
    fmt.Println("got", n, "bytes.")
    buf = append(buf, tmp[:n]...)
    header, err := ipv4.ParseHeader(buf)
    if err != nil {
      fmt.Println("Couldn't parse packet, dropping connnection.")
      return
    }
    if header.TotalLen == 0 && len(buf) > 0 {
      fmt.Println("Buffer is not parserable!")
      return
    }
    if (header.TotalLen > len(buf)) {
      fmt.Println("Reading more up to %d\n", header.TotalLen)
      continue
    }
    packetData := buf[0:header.TotalLen]
    fmt.Printf("PACKET LEN:%d, bufLen:%d\n", header.TotalLen, len(buf))

    buf = buf[header.TotalLen:]

    fmt.Printf("Packet to %s\n", header.Dst)

    go func(){

      _, ip, tcp, recompilePacket, err := parseTCPPacket(packetData)
      if err != nil {
        fmt.Println(err)
        return
      }

      dstIP := ip.DstIP
      if isLocalIP(dstIP.String()) {
        fmt.Printf("DESTINATION IS SELF: %s\n", dstIP.String())
        return
      }

      // Change source IP

      savedIP := ip.SrcIP
      savedPort := tcp.SrcPort
      ip.SrcIP = myOutboundIP
      modPacket, err := recompilePacket()
      if err != nil {
        fmt.Println(err)
        return
      }

      // Send modified packet

      src := fmt.Sprintf("%s:%d", savedIP.String(), tcp.SrcPort)
      ipconn := srcToIPConn[src]
      if ipconn == nil {
        fmt.Printf("Dialing IP %s\n", dstIP.String())
        ipconn, err = net.DialIP("ip:tcp", nil, &net.IPAddr{IP: dstIP.To4()})
        if err != nil {
          fmt.Println(err)
          return
        }
        fmt.Printf("Dialed %s\n", dstIP.String())
        srcToIPConn[src] = ipconn
        go handleRepliesFromIPConn(ipconn, savedIP, savedPort, src)
      }
      err = sendViaSocket(modPacket, ip.DstIP)
      if err != nil {
        fmt.Println("Error while writing MSG:", err)
      }

    }()

  }

}

func (p *Proxy) copy(from, to net.TCPConn, wg *sync.WaitGroup) {
  defer wg.Done()
  select {
  case <-p.done:
    return
  default:
    if _, err := io.Copy(&to, &from); err != nil {
      p.log.WithField("err", err).Errorln("Error from copy")
      p.Stop()
      return
    }
  }
}

func itod(i uint) string {
        if i == 0 {
                return "0"
        }

        // Assemble decimal in reverse order.
        var b [32]byte
        bp := len(b)
        for ; i > 0; i /= 10 {
                bp--
                b[bp] = byte(i%10) + '0'
        }

        return string(b[bp:])
}

var remoteAddr *string = flag.String("r", "boom", "remote address")

func main() {

    controlC := make(chan os.Signal)
    signal.Notify(controlC, os.Interrupt)
    go func(){
      <-controlC
      fmt.Println("Exiting after Ctrl+C")
      os.Exit(0)
    }()

    flag.Parse();
    log.SetLevel(log.InfoLevel)

    p := NewProxy(*remoteAddr)

    if os.Geteuid() != 0 {
      p.log.Infoln("Lower ports may be not accessible without root rights.")
    }

    p.Start()

    fmt.Println("Server started.")
    select{}
}
