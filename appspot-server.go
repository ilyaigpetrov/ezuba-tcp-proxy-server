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
  "syscall"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "time"

  "github.com/ilyaigpetrov/parse-tcp-go"
  "github.com/Sirupsen/logrus"
  "log"
)

var errlog = log.New(os.Stderr,
    "ERROR: ",
    log.Lshortfile)

var infolog = log.New(os.Stdout,
    "", log.Lshortfile)

func xor42(data []byte) []byte {
  for i, b := range data {
    data[i] = b ^ 42
  }
  return data
}

var clientConnection net.Conn

type Proxy struct {
  from string
  fromTCP *net.TCPAddr
  done chan struct{}
  log  *logrus.Entry
}

type clientAddr struct {
  ip net.IP
  port layers.TCPPort
}

var clientIP string

func NewProxy(from string) *Proxy {

  logrus.SetLevel(logrus.InfoLevel)
  return &Proxy{
    from: from,
    done: make(chan struct{}),
    log: logrus.WithFields(logrus.Fields{
      "from": from,
    }),
  }

}

func processPacket(packetData []byte) {

  packet, err := parseTCP.ParseTCPPacket(packetData)
  if err != nil {
    errlog.Println(err)
    errlog.Println(hex.Dump(packetData))
    return
  }
  ip := packet.IP
  tcp := packet.TCP
  recompile := packet.Recompile
  addr, ok := openPortToClientAddr[fmt.Sprintf("%d", tcp.DstPort)]
  if !ok {
    if
        int(tcp.DstPort) != 22 &&
        !ip.SrcIP.Equal(net.ParseIP("169.254.169.254")) &&
        !ip.SrcIP.Equal(net.ParseIP(clientIP)) {
      infolog.Printf("Reject: %s:%d to %s:%d<!\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
      packet.Print(100)
      if tcp.SYN && tcp.ACK && ip.DstIP.Equal(myOutboundIP) {
        openPortToSynAck[tcp.DstPort.String()] = packetData
        infolog.Printf("Added syn ack for %s\n", tcp.DstPort.String())
        infolog.Printf("2.Added syn ack for %s\n", string(tcp.DstPort))
      }
    }
    return
  }
  infolog.Println("SENDING BACK:")
  packet.Print(100)

  ip.DstIP = addr.ip
  tcp.DstPort = addr.port
  packetData, err = recompile()
  if err != nil {
    errlog.Println(err)
    return
  }
  _, err = io.Copy(clientConnection, bytes.NewReader(packetData))
  //_, err = clientConnection.Write(packetData)
  if err != nil {
    errlog.Println(err)
  }

}

func (p *Proxy) Start() error {
  p.log.Infoln("Starting proxy")

  rawTCPSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
  if err != nil {
    panic(err)
  }
  go func(){

    defer syscall.Close(rawTCPSocket)
    for {
      packetData := make([]byte, 65535)
      n, _, err := syscall.Recvfrom(rawTCPSocket, packetData, 0)
      if err != nil {
        errlog.Println(err)
        break
      }
      packetData = packetData[:n]
      processPacket(packetData)

    }

  }()

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
      clientConnection, err = listener.Accept()
      if clientConnection == nil {
        p.log.WithField("err", err).Errorln("Nil clientConnection")
        panic(err)
      }
      la := clientConnection.LocalAddr()
      if (la == nil) {
        panic("Connection lost!")
      }
      infolog.Printf("Connection from %s to %s\n", la.String(), clientConnection.RemoteAddr().String())

      if err == nil {
	clientIP = clientConnection.RemoteAddr().String()
	parts := strings.Split(clientIP, ":")
	clientIP = parts[0]
        go p.handle(clientConnection)
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
var srcToSiteConn = make(map[string]net.Conn)
var openPortToClientAddr = make(map[string]clientAddr)
var openPortToSynAck = make(map[string][]byte) // Attack is possible by site which bombs us with syn-ack packets

var packetBuffer = make([]byte, 65535)

func handleRepliesFromSiteConn(siteConnection net.Conn, originalIP net.IP, originalPort layers.TCPPort, src string, closeSiteConnection func(net.Conn)) {

  defer closeSiteConnection(siteConnection)
  for {
    _, err := siteConnection.Read(packetBuffer)
    if err != nil {
      if err == io.EOF {
        time.Sleep(time.Second * 20) // Wait for FIN packets to pass.
      } else {
        errlog.Println(err)
      }
      break
    }
  }

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

func getSrcPortFromConnection(conn net.Conn) string {

  parts := strings.Split( conn.LocalAddr().String(), ":" )
  return parts[1]

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
        errlog.Println("read error:", err)
      }
      break
    }
    infolog.Println("got", n, "bytes.")
    buf = append(buf, tmp[:n]...)
    header, err := ipv4.ParseHeader(buf)
    if err != nil {
      infolog.Println("Couldn't parse packet, dropping connnection.")
      return
    }
    if header.TotalLen == 0 && len(buf) > 0 {
      errlog.Println("Buffer is not parserable!")
      return
    }
    if (header.TotalLen > len(buf)) {
      infolog.Println("Reading more up to %d\n", header.TotalLen)
      continue
    }

    packetData := buf[0:header.TotalLen]

    infolog.Printf("PACKET LEN:%d, bufLen:%d\n", header.TotalLen, len(buf))

    buf = buf[header.TotalLen:]

    packet, err := parseTCP.ParseTCPPacket(packetData)
    if err != nil {
      errlog.Println(err)
      errlog.Println(hex.Dump(packetData))
      return
    }
    ip := packet.IP
    tcp := packet.TCP
    infolog.Println("RECEIVED FROM CLIENT:")
    packet.Print(100)

    dstIP := ip.DstIP
    if isLocalIP(dstIP.String()) {
      infolog.Printf("DESTINATION IS SELF: %s\n", dstIP.String())
      return
    }

    savedIP := ip.SrcIP
    savedPort := tcp.SrcPort
    src := fmt.Sprintf("%s:%d", savedIP.String(), tcp.SrcPort)
    dst := fmt.Sprintf("%s:%d", dstIP.String(), tcp.DstPort)

    if len(tcp.Payload) == 0 && !tcp.SYN {
      return
    }

    closeSiteConnection := func(siteConnection net.Conn) {

      srcPort := getSrcPortFromConnection(siteConnection)
      infolog.Printf("CLOSE CONNECTION for port %s\n", srcPort)
      delete(openPortToClientAddr, srcPort)
      siteConnection.Close()
      delete(srcToSiteConn, src)

      ip.SrcIP = ip.DstIP
      tcp.SrcPort = tcp.DstPort
      ip.DstIP = savedIP
      tcp.DstPort = savedPort

      newTcp := &layers.TCP{FIN: true}
      newTcp.DstPort = savedPort

      options := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths: true,
      }

      newTcp.SetNetworkLayerForChecksum(ip)

      buffer := gopacket.NewSerializeBuffer()
      gopacket.SerializeLayers(buffer, options,
          ip,
          newTcp,
      )
      outgoingPacket := buffer.Bytes()
      _, err = io.Copy(clientConnection, bytes.NewReader(outgoingPacket))
      //_, err = clientConnection.Write(outgoingPacket)
      if err != nil {
        errlog.Println(err)
      }

    }


    siteConnection := srcToSiteConn[src]
    if tcp.SYN && siteConnection != nil {
      closeSiteConnection(siteConnection)
      siteConnection = nil
    }
    if siteConnection == nil {
      infolog.Printf("No con for %s,\n%v\n", src, srcToSiteConn)
      infolog.Printf("Dialing %s...\n", dst)
      siteConnection, err := net.Dial("tcp", dst)
      if err != nil {
        errlog.Println(err)
        return
      }
      if siteConnection == nil {
        errlog.Println("Site con is nil")
        return
      }
      srcToSiteConn[src] = siteConnection
      openPort := getSrcPortFromConnection(siteConnection)
      openPortToClientAddr[openPort] = clientAddr{ ip: savedIP, port: savedPort }
      infolog.Printf("Added %s to open ports\n", openPort)
      synack, ok := openPortToSynAck[openPort]
      if ok {
	delete(openPortToSynAck, openPort)
	infolog.Println("Process saved synack")
	processPacket(synack)
      }

      go handleRepliesFromSiteConn(siteConnection, savedIP, savedPort, src, closeSiteConnection)
    } else {
      infolog.Println("Sending payload to site...")
      packet.Print(100)
      _, err = io.Copy(siteConnection, bytes.NewReader(tcp.Payload))
      if err != nil {
        errlog.Println(err)
        closeSiteConnection(siteConnection)
      }
    }


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
      infolog.Println("Exiting after Ctrl+C")
      os.Exit(0)
    }()

    flag.Parse();
    logrus.SetLevel(logrus.InfoLevel)

    p := NewProxy(*remoteAddr)

    if os.Geteuid() != 0 {
      p.log.Infoln("Lower ports may be not accessible without root rights.")
    }

    p.Start()

    infolog.Println("Server started.")
    select{}
}
