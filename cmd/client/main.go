package main

import (
	"bufio"
	"flag"
	"os"

	log "github.com/sirupsen/logrus"
	"net"
)

// Flags
var (
	proxyAddr *string
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

	proxyAddr = flag.String("proxy", "localhost:4242", "Target address to redirect traffic to")

	flag.Parse()
	remote, err := net.Dial("tcp", *proxyAddr)
	if err != nil {
		log.Infof("failed to connect to remote '%v' with error: %v  ", *proxyAddr, err)
	}
	defer remote.Close()

	var buf [128]byte

	reader := bufio.NewReader(os.Stdin)
	for {
		text, err0 := reader.ReadString('\n')
		if err0 != nil {
			log.Fatalf("read from console failed with reason: %v", err)
		}
		n, err := remote.Write([]byte(text))
		if err != nil {
			log.Fatalf("write to remote connection terminated with reason: %v", err)
		}
		log.Infof("client writing to %v %d  bytes", remote.RemoteAddr(), n)
		n, err = remote.Read(buf[:])
		if err != nil {
			log.Fatalf("read from remote connection terminated with reason: %v", err)
		}
		log.Infof("client reading from %v %d  bytes", remote.RemoteAddr(), n)
		os.Stderr.Write(buf[:n])

	}
}
