package main

import (
  "fmt"
  "log"
  "net/http"
  "os"
  "io"
  "errors"

  "golang.org/x/net/ipv4"
)

var infolog = log.New(os.Stdout,
    "", log.Lshortfile)

var errlog = log.New(os.Stderr,
    "", log.Lshortfile)

func main() {
  http.HandleFunc("/", handle)
  http.HandleFunc("/iptables", iptablesHandler)
  log.Print("Listening on port 8080")
  infolog.Fatal(http.ListenAndServe(":8080", nil))
}

func handle(w http.ResponseWriter, r *http.Request) {
  if r.URL.Path != "/" {
    http.NotFound(w, r)
    return
  }
  fmt.Fprint(w, "<!doctype html><title>ezuba server</title>" +
    "Ezuba server runs on this site. <a href=\"https://github.com/ilyaigpetrov/ezuba-tcp-proxy-server\">Server source codes</a>.  ")
}

func readBody(body io.ReadCloser, errchan chan error) {
  buf := make([]byte, 0, 65535) // big buffer
  tmp := make([]byte, 4096)     // using small tmo buffer for demonstrating
  for {
    n, err := body.Read(tmp)
    if err != nil {
      if err != io.EOF {
        errlog.Println("read error:", err)
      }
      errchan <- err
      return
    }
    infolog.Println("Got", n, "bytes from POST body.")
    buf = append(buf, tmp[:n]...)
    header, err := ipv4.ParseHeader(buf)
    if err != nil {
      infolog.Println("Couldn't parse packet, dropping connnection.")
      errchan <- err
      return
    }
    if header.TotalLen == 0 && len(buf) > 0 {
      errchan <- errors.New("Buffer is not parsable")
      return
    }
    if (header.TotalLen > len(buf)) {
      infolog.Println("Reading more up to %d\n", header.TotalLen)
      continue
    }

    packetData := buf[0:header.TotalLen]
    _ = packetData // TODO

    infolog.Printf("PACKET LEN:%d, bufLen:%d\n", header.TotalLen, len(buf))

    buf = buf[header.TotalLen:]
  }

}

func writeResponse(w http.ResponseWriter, errchan chan error) {
  for {
    fmt.Fprintf(w, "Hello, try posting after me!")
  }
}


func iptablesHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "POST" {
    fmt.Fprint(w, "Try POST method!")
    return
  }

  userSecret := r.URL.Query().Get("user-secret")
  if userSecret == "" {
    fmt.Fprintf(w, "Provide user-secret, e.g. ?user-secret=foobar")
    return
  }

  errchan := make(chan error)
  go readBody(r.Body, errchan)
  go writeResponse(w, errchan)
  var err error
  err = <- errchan
  errlog.Println("FINITA:", err)
}
