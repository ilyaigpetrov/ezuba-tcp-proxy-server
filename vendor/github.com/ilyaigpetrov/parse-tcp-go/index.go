package parseTCP

import (
  "errors"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "fmt"
  "gopkg.in/oleiade/reflections.v1"
  "strings"
  "math"
  "encoding/hex"
)

type Packet struct {
  Gopacket gopacket.Packet
  IP *layers.IPv4
  TCP *layers.TCP
  Recompile func() ([]byte, error)
  Print func(...int)
}

func ParseTCPPacket(packetData []byte) (packet Packet, err error) {

  packet.Gopacket = gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

  ipLayer := packet.Gopacket.Layer(layers.LayerTypeIPv4)
  if ipLayer == nil {
    err = errors.New("No IP layer!")
    fmt.Println(hex.Dump(packetData))
    return
  }
  packet.IP = ipLayer.(*layers.IPv4)
  ip := packet.IP

  tcpLayer := packet.Gopacket.Layer(layers.LayerTypeTCP)
  if tcpLayer == nil {
    err = errors.New("No TCP layer!")
    return
  }
  packet.TCP = tcpLayer.(*layers.TCP)
  tcp := packet.TCP

  packet.Recompile = func() ([]byte, error) {

    options := gopacket.SerializeOptions{
      ComputeChecksums: true,
      FixLengths: true,
    }
    newBuffer := gopacket.NewSerializeBuffer()
    tcp.SetNetworkLayerForChecksum(ip)
    err := gopacket.SerializePacket(newBuffer, options, packet.Gopacket)
    if err != nil {
      return nil, err
    }
    return newBuffer.Bytes(), nil

  }
  packet.Print = func(payloadLimits ...int) {

    fmt.Printf("Packet from %s:%d to %s:%d %d", ip.SrcIP.String(), tcp.SrcPort, ip.DstIP.String(), tcp.DstPort, tcp.Seq)
    flags := strings.Split("FIN SYN RST PSH ACK URG ECE CWR NS", " ")
    for _, flag := range flags {
      val, err := reflections.GetField(tcp, flag)
      if err != nil {
        fmt.Println(err, "REFLECT ERROR!")
      }
      if val.(bool) {
        fmt.Printf(" %s", flag)
      }
    }
    fmt.Printf("\n")
    payloadLimit := 1000
    if len(payloadLimits) > 0 {
      payloadLimit = payloadLimits[0]
    }
    if len(tcp.Payload) != 0 {
      fmt.Println("TCP PAYLOAD:", string(tcp.Payload[:int(math.Min(float64(len(tcp.Payload)), float64(payloadLimit)))]))
    }
  }

  return

}
