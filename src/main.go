package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4sni/sni"
)

const (
	ETH_P_ALL = 0x0003
	ETH_HLEN  = 14
)

type SNIExtractor struct {
	fd          int
	packetCount uint64
	sniCount    uint64
	startTime   time.Time
	sniCache    map[string]time.Time
}

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

func main() {
	extractor := &SNIExtractor{
		startTime: time.Now(),
		sniCache:  make(map[string]time.Time),
	}

	if err := extractor.init(); err != nil {
		log.Fatal(err)
	}
	defer extractor.close()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Stats ticker
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	go func() {
		for range sigChan {
			fmt.Printf("\n\nShutting down...\n")
			extractor.close()
			os.Exit(0)
		}
	}()

	extractor.run()
}

func (e *SNIExtractor) init() error {
	// Create AF_PACKET raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("failed to create raw socket (need root privileges): %v", err)
	}

	e.fd = fd

	// Set receive buffer size for better performance
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024); err != nil {
		log.Printf("Warning: failed to set receive buffer size: %v", err)
	}

	return nil
}

func (e *SNIExtractor) close() {
	if e.fd != 0 {
		syscall.Close(e.fd)
	}
}

func (e *SNIExtractor) run() {
	buf := make([]byte, 65536)

	for {
		n, _, err := syscall.Recvfrom(e.fd, buf, 0)
		if err != nil {
			if err != syscall.EAGAIN && err != syscall.EINTR {
				log.Printf("Error receiving packet: %v", err)
			}
			continue
		}

		e.packetCount++
		e.processPacket(buf[:n])

		// Clean old cache entries every 1000 packets
		if e.packetCount%1000 == 0 {
			e.cleanCache()
		}
	}
}

func (e *SNIExtractor) processPacket(packet []byte) {
	if len(packet) < ETH_HLEN {
		return
	}

	ethType := binary.BigEndian.Uint16(packet[12:14])
	payload := packet[ETH_HLEN:]

	var sni string
	var flowKey FlowKey
	var proto string

	switch ethType {
	case 0x0800: // IPv4
		sni, flowKey, proto = e.processIPv4(payload)
	case 0x86DD: // IPv6
		sni, flowKey, proto = e.processIPv6(payload)
	default:
		return
	}

	if sni != "" {
		// Check cache to avoid duplicate logs
		cacheKey := fmt.Sprintf("%s:%d->%s:%d:%s",
			flowKey.SrcIP, flowKey.SrcPort,
			flowKey.DstIP, flowKey.DstPort, sni)

		if lastSeen, exists := e.sniCache[cacheKey]; !exists || time.Since(lastSeen) > 60*time.Second {
			e.sniCache[cacheKey] = time.Now()
			e.sniCount++
			e.printSNI(flowKey, sni, proto)
		}
	}
}

func (e *SNIExtractor) processIPv4(packet []byte) (string, FlowKey, string) {
	if len(packet) < 20 {
		return "", FlowKey{}, ""
	}

	versionIHL := packet[0]
	ipHeaderLen := int((versionIHL & 0x0F) * 4)
	if ipHeaderLen < 20 || len(packet) < ipHeaderLen {
		return "", FlowKey{}, ""
	}

	protocol := packet[9]
	srcIP := net.IP(packet[12:16]).String()
	dstIP := net.IP(packet[16:20]).String()

	// Check for fragmentation
	flagsFrags := binary.BigEndian.Uint16(packet[6:8])
	if (flagsFrags & 0x1FFF) != 0 { // Fragment offset != 0
		return "", FlowKey{}, ""
	}

	transportPacket := packet[ipHeaderLen:]

	switch protocol {
	case 6: // TCP
		return e.processTCP(transportPacket, srcIP, dstIP)
	case 17: // UDP
		return e.processUDP(transportPacket, srcIP, dstIP)
	}

	return "", FlowKey{}, ""
}

func (e *SNIExtractor) processIPv6(packet []byte) (string, FlowKey, string) {
	if len(packet) < 40 {
		return "", FlowKey{}, ""
	}

	nextHeader := packet[6]
	srcIP := net.IP(packet[8:24]).String()
	dstIP := net.IP(packet[24:40]).String()

	// Skip extension headers if present
	offset := 40
	for isExtensionHeader(nextHeader) && offset < len(packet) {
		if offset+2 > len(packet) {
			return "", FlowKey{}, ""
		}
		extLen := int(packet[offset+1])*8 + 8
		nextHeader = packet[offset]
		offset += extLen
	}

	transportPacket := packet[offset:]

	switch nextHeader {
	case 6: // TCP
		return e.processTCP(transportPacket, srcIP, dstIP)
	case 17: // UDP
		return e.processUDP(transportPacket, srcIP, dstIP)
	}

	return "", FlowKey{}, ""
}

func (e *SNIExtractor) processTCP(packet []byte, srcIP, dstIP string) (string, FlowKey, string) {
	if len(packet) < 20 {
		return "", FlowKey{}, ""
	}

	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])
	dataOffset := (packet[12] >> 4) * 4

	flowKey := FlowKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Filter for common TLS ports in userspace
	if srcPort != 443 && dstPort != 443 &&
		srcPort != 8443 && dstPort != 8443 &&
		srcPort != 853 && dstPort != 853 {
		return "", flowKey, ""
	}

	if int(dataOffset) > len(packet) {
		return "", flowKey, ""
	}

	payload := packet[dataOffset:]

	// Check for TLS handshake
	if len(payload) > 5 && payload[0] == 0x16 && (payload[1] == 0x03 || payload[1] == 0x02) {
		sni := extractSNIFromTLS(payload)
		return sni, flowKey, "TCP"
	}

	return "", flowKey, ""
}

func (e *SNIExtractor) processUDP(packet []byte, srcIP, dstIP string) (string, FlowKey, string) {
	if len(packet) < 8 {
		return "", FlowKey{}, ""
	}

	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])

	flowKey := FlowKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Filter for common QUIC ports in userspace
	if srcPort != 443 && dstPort != 443 &&
		srcPort != 8443 && dstPort != 8443 &&
		srcPort != 853 && dstPort != 853 {
		return "", flowKey, ""
	}

	payload := packet[8:]

	// Check for QUIC
	if len(payload) > 0 && (payload[0]&0x80) != 0 {
		return extractSNIFromQUIC(payload), flowKey, "UDP"
	}

	return "", flowKey, ""
}

func extractSNIFromTLS(payload []byte) string {
	sni, _ := sni.ParseTLSClientHelloSNI(payload)
	return sni
}

func extractSNIFromQUIC(payload []byte) string {
	sni, _ := sni.ParseQUICClientHelloSNI(payload)
	return sni
}

func isExtensionHeader(nextHeader uint8) bool {
	switch nextHeader {
	case 0, 43, 44, 60: // Hop-by-hop, Routing, Fragment, Destination options
		return true
	}
	return false
}

func (e *SNIExtractor) cleanCache() {
	now := time.Now()
	for key, lastSeen := range e.sniCache {
		if now.Sub(lastSeen) > 5*time.Minute {
			delete(e.sniCache, key)
		}
	}
}

func (e *SNIExtractor) printSNI(flowKey FlowKey, sni string, proto string) {
	timestamp := time.Now().Format("15:04:05.000")

	const (
		colorReset  = "\033[0m"
		colorGreen  = "\033[32m"
		colorYellow = "\033[33m"
		colorCyan   = "\033[36m"
	)

	protoColor := colorCyan
	if proto == "TCP" {
		protoColor = colorGreen
	}

	fmt.Printf("%s,%s%s%s,%s:%d,%s:%d,%s%s%s\n",
		timestamp,
		protoColor, proto, colorReset,
		flowKey.SrcIP, flowKey.SrcPort,
		flowKey.DstIP, flowKey.DstPort,
		colorYellow, sni, colorReset,
	)
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
