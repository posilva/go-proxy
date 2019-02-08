package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io"

	"crypto/tls"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// TLS protocol constants
const (
	recordTypeHandshake uint8  = 22
	typeClientHello     uint8  = 1
	extensionServerName uint16 = 0
	sniTypeHostname     uint8  = 0
)

// Flags
var (
	port       *int
	targetAddr *string
	nativeCopy *bool
	stripSSL   *bool
)

var (
	tlsCert   tls.Certificate
	tlsConfig *tls.Config
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

	cert, err := tls.LoadX509KeyPair("localhost.pem", "localhost-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	tlsCert = cert
	tlsConfig = &tls.Config{Certificates: []tls.Certificate{tlsCert}}

}

type prefixConn struct {
	net.Conn
	io.Reader
}

func (p prefixConn) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}

func main() {
	stripSSL = flag.Bool("strip-ssl", true, "Strip SSL")
	nativeCopy = flag.Bool("native-copy", true, "Use Native Copy")
	port = flag.Int("port", 4242, "Listening port")
	targetAddr = flag.String("target", "google.com:80", "Target address to redirect traffic to")

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

		go doProxy(conn, *targetAddr)
	}
}

func doProxy(conn net.Conn, address string) {
	defer conn.Close()
	var proxyConn net.Conn
	if *stripSSL {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		var buf bytes.Buffer
		if _, err := io.CopyN(&buf, conn, 1+2+2); err != nil {
			log.Error(err)
			return
		}

		length := binary.BigEndian.Uint16(buf.Bytes()[3:5])
		if _, err := io.CopyN(&buf, conn, int64(length)); err != nil {
			log.Error(err)
			return
		}

		sni, ok := parseClientHello(buf.Bytes())
		if ok {
			log.Warnf("Got a connection with SNI %q", sni)
		}
		c := prefixConn{
			Conn:   conn,
			Reader: io.MultiReader(&buf, conn),
		}
		conn.SetReadDeadline(time.Time{})
		proxyConn = tls.Server(c, tlsConfig)
	} else {
		proxyConn = conn
	}

	log.Print("proxy: handling new connection")
	remote, err := net.Dial("tcp", address)
	if err != nil {
		log.Infof("failed to connect to remote '%v' with error: %v  ", address, err)
		return
	}
	go copyTo(proxyConn, remote, *nativeCopy)
	_, err = copyTo(remote, proxyConn, *nativeCopy)
	if err != nil {
		log.Infof("failed to write to remote: %v", err)
		return
	}
}
func copyTo(fromConn, toConn net.Conn, native bool) (int64, error) {
	if native {
		return io.Copy(toConn, fromConn)
	}
	var buf [128]byte

	for {

		n, err := fromConn.Read(buf[:])
		if err != nil {
			log.Infof("source connection terminated with reason: %v", err)
			return 0, err
		}
		log.Infof("proxy reading from %v %d  bytes", fromConn.RemoteAddr(), n)

		n, err = toConn.Write(buf[:n])
		if err != nil {
			log.Infof("target connection terminated with reason: %v", err)
			return 0, err
		}
		log.Infof("proxy writing to %v %d  bytes", toConn.RemoteAddr(), n)
	}

}
func copyToStdErr(conn net.Conn) {
	defer conn.Close()
	log.Print("copyToStdErr: handling new connection")
	var buf [128]byte
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf[:])
		if err != nil {
			log.Infof("connection terminated with reason: %v", err)
			return
		}
		os.Stderr.Write(buf[:n])
	}
}

// parseClientHello tries to parse a TLS record and extract the SNI.
// Returns the parsed SNI and whether the message looks like TLS (even if no SNI
// Extension is present, the message might still appear to be TLS).
func parseClientHello(record []byte) (string, bool) {
	input := cryptobyte.String(record)

	// parse record, but skip version
	var contentType uint8
	var fragment cryptobyte.String
	if !input.ReadUint8(&contentType) ||
		contentType != recordTypeHandshake ||
		!input.Skip(2) || !input.ReadUint16LengthPrefixed(&fragment) {
		return "", false
	}

	// parse Handshake message
	var msgType uint8
	var clientHello cryptobyte.String
	if !fragment.ReadUint8(&msgType) || msgType != typeClientHello ||
		!fragment.ReadUint24LengthPrefixed(&clientHello) {
		return "", false
	}

	// Parse Client Hello message (ignore random, SID, cipher suites,
	// compression methods, only preserve extensions).
	var tlsVersion uint16
	var ignore, exts cryptobyte.String
	if !clientHello.ReadUint16(&tlsVersion) ||
		!(tlsVersion >= tls.VersionTLS10 && tlsVersion <= tls.VersionTLS12) ||
		!clientHello.Skip(32) ||
		!clientHello.ReadUint8LengthPrefixed(&ignore) ||
		!clientHello.ReadUint16LengthPrefixed(&ignore) ||
		!clientHello.ReadUint8LengthPrefixed(&ignore) ||
		!clientHello.ReadUint16LengthPrefixed(&exts) {
		return "", false
	}

	// Parse extensions
	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) ||
			!exts.ReadUint16LengthPrefixed(&extData) {
			return "", false
		}
		if extType != extensionServerName {
			continue
		}

		var serverNameList cryptobyte.String
		if !extData.ReadUint16LengthPrefixed(&serverNameList) {
			return "", false
		}
		for !serverNameList.Empty() {
			var nameType uint8
			if !serverNameList.ReadUint8(&nameType) {
				return "", false
			}
			if nameType != sniTypeHostname {
				continue
			}

			var hostName cryptobyte.String
			if !serverNameList.ReadUint16LengthPrefixed(&hostName) {
				return "", false
			}
			return string(hostName), true
		}

		// extensions must be unique
		return "", false
	}

	// server_name extension not found
	return "", true
}
