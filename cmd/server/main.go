package main

import (
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"time"
)

// Flags
var (
	port *int
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
	log.SetReportCaller(true)
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stderr)

	// Only log the warning severity or above.
	log.SetLevel(log.WarnLevel)
}

func main() {
	port = flag.Int("port", 4000, "Listening port")

	flag.Parse()

	ln, err := net.Listen("tcp", "localhost:"+string(strconv.Itoa(*port)))
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("listen on port: %v", *port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Infof("failed to accept connection: %v", err)
		}

		go echo(conn)
	}
}
func echo(conn net.Conn) {
	defer conn.Close()
	log.Print("echo: server handling new connection")
	var buf [128]byte
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf[:])
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			log.Infof("read failed with reason: %v", err)

		} else if err != nil {
			log.Infof("connection terminated with reason: %v", err)
			return
		}
		log.Infof("server reading from %v %d  bytes", conn.RemoteAddr(), n)
		conn.Write(buf[:n])
	}
}
