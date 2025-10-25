package sni

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4sni/log"
)

const (
	ETH_P_ALL = 0x0003
	ETH_HLEN  = 14
)

const (
	tlsContentTypeHandshake uint8 = 22
	tlsHandshakeClientHello uint8 = 1
)

const (
	tlsExtServerName uint16 = 0
)

type parseErr string

func (e *SNIExtractor) Init() error {
	// Create AF_PACKET raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("failed to create raw socket (need root privileges): %v", err)
	}

	e.fd = fd

	// Set receive buffer size for better performance
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024); err != nil {
		log.Infof("Warning: failed to set receive buffer size: %v", err)
	}

	return nil
}

func (e *SNIExtractor) Close() {
	if e.fd != 0 {
		syscall.Close(e.fd)
	}
}

func (e *SNIExtractor) Run() {
	buf := make([]byte, 65536)

	for {
		n, _, err := syscall.Recvfrom(e.fd, buf, 0)
		if err != nil {
			if err != syscall.EAGAIN && err != syscall.EINTR {
				log.Infof("Error receiving packet: %v", err)
			}
			continue
		}

		e.processPacket(buf[:n])
	}
}

func NewTCPStreamTracker() *TCPStreamTracker {
	tracker := &TCPStreamTracker{
		streams: make(map[TCPStreamKey]*TCPStream),
	}

	// Clean up old streams periodically
	go tracker.Cleanup()

	return tracker
}

func (t *TCPStreamTracker) Cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		t.mu.Lock()
		now := time.Now()
		for key, stream := range t.streams {
			if now.Sub(stream.lastSeen) > 60*time.Second {
				delete(t.streams, key)
			}
		}
		t.mu.Unlock()
	}
}

func (t *TCPStreamTracker) ProcessPacket(packet []byte, srcIP, dstIP string) (string, FlowKey) {
	if len(packet) < 20 {
		return "", FlowKey{}
	}

	srcPort := binary.BigEndian.Uint16(packet[0:2])
	dstPort := binary.BigEndian.Uint16(packet[2:4])
	dataOffset := (packet[12] >> 4) * 4
	flags := packet[13]

	flowKey := FlowKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Skip packets without payload
	if int(dataOffset) >= len(packet) {
		return "", flowKey
	}

	payload := packet[dataOffset:]
	if len(payload) == 0 {
		return "", flowKey
	}

	// Create stream key (normalize direction)
	streamKey := TCPStreamKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	stream, exists := t.streams[streamKey]
	if !exists {
		// Also check reverse direction
		reverseKey := TCPStreamKey{
			SrcIP:   dstIP,
			DstIP:   srcIP,
			SrcPort: dstPort,
			DstPort: srcPort,
		}
		if stream, exists = t.streams[reverseKey]; exists {
			streamKey = reverseKey
		}
	}

	// RST or FIN - clean up stream
	if flags&0x05 != 0 {
		if exists {
			delete(t.streams, streamKey)
		}
		return "", flowKey
	}

	// Create new stream if needed
	if !exists {
		stream = &TCPStream{
			buffer:   make([]byte, 0, 4096),
			lastSeen: time.Now(),
		}
		t.streams[streamKey] = stream
	}

	stream.lastSeen = time.Now()

	// If we already found SNI for this stream, skip
	if stream.sniFound {
		return "", flowKey
	}

	// Append payload to buffer
	stream.buffer = append(stream.buffer, payload...)

	// Try to extract SNI from accumulated buffer
	sni := t.tryExtractSNI(stream)
	if sni != "" {
		stream.sniFound = true
		// Clean up large buffer after SNI found
		if len(stream.buffer) > 1024 {
			stream.buffer = stream.buffer[:1024]
		}
		return sni, flowKey
	}

	// Limit buffer size to prevent memory issues
	if len(stream.buffer) > 16384 {
		stream.buffer = stream.buffer[8192:]
	}

	return "", flowKey
}

func (e *SNIExtractor) processTCP(packet []byte, srcIP, dstIP string) (string, FlowKey, string) {
	// Use the stream tracker instead of direct parsing
	sni, flowKey := e.TcpTracker.ProcessPacket(packet, srcIP, dstIP)

	if sni != "" {
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
		sni, _ := ParseQUICClientHelloSNI(payload)
		return sni, flowKey, "UDP"
	}

	return "", flowKey, ""
}

func (t *TCPStreamTracker) tryExtractSNI(stream *TCPStream) string {
	buf := stream.buffer

	// Look for TLS handshake in the buffer
	for i := 0; i < len(buf)-5; i++ {
		// Check for TLS handshake record
		if buf[i] != 0x16 {
			continue
		}

		// Check TLS version (0x0301 to 0x0304)
		if buf[i+1] != 0x03 || buf[i+2] > 0x04 {
			continue
		}

		// Get record length
		recordLen := int(buf[i+3])<<8 | int(buf[i+4])
		if i+5+recordLen > len(buf) {
			// Need more data
			break
		}

		// Try to parse SNI from this position
		if sni, ok := ParseTLSClientHelloSNI(buf[i:]); ok && sni != "" {
			return sni
		}
	}

	return ""
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

func isExtensionHeader(nextHeader uint8) bool {
	switch nextHeader {
	case 0, 43, 44, 60: // Hop-by-hop, Routing, Fragment, Destination options
		return true
	}
	return false
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
		e.printSNI(flowKey, sni, proto)
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

func (e parseErr) Error() string { return string(e) }

var errNotHello = parseErr("not a ClientHello")

// isValidSNIChar checks if a byte is valid in an SNI hostname
func isValidSNIChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_'
}

// validateSNI checks if the SNI string contains only valid characters
func validateSNI(sni string) bool {
	if len(sni) == 0 {
		return false
	}
	for i := 0; i < len(sni); i++ {
		if !isValidSNIChar(sni[i]) {
			log.Tracef("Invalid SNI char at position %d: 0x%02x in %q", i, sni[i], sni)
			return false
		}
	}
	// Additional validation: must contain at least one dot or be localhost
	if sni != "localhost" && !contains(sni, '.') {
		return false
	}
	return true
}

func contains(s string, char byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == char {
			return true
		}
	}
	return false
}

func ParseTLSClientHelloSNI(b []byte) (string, bool) {
	log.Tracef("TCP Payload=%v", len(b))

	// Fast path: Check if this looks like a TLS handshake
	if len(b) < 5 || b[0] != 0x16 {
		return "", false
	}

	// Fast path: Check TLS version (should be 0x0301, 0x0302, 0x0303, or 0x0304)
	if b[1] != 0x03 || b[2] > 0x04 {
		return "", false
	}

	i := 0
	for i+5 <= len(b) {
		if b[i] != 0x16 {
			i++
			continue
		}
		recLen := int(b[i+3])<<8 | int(b[i+4])
		if recLen <= 0 || i+5+recLen > len(b) {
			log.Tracef("TLS: record truncated at %d", i)
			return "", false
		}
		rec := b[i+5 : i+5+recLen]
		if len(rec) < 4 {
			return "", false
		}
		if rec[0] == 0x01 {
			hl := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
			if 4+hl > len(rec) {
				log.Tracef("TLS: ClientHello truncated")
				return "", false
			}
			ch := rec[4 : 4+hl]
			sni, hasECH, _ := parseTLSClientHelloMeta(ch)
			if sni == "" {
				if hasECH {
					log.Tracef("TLS: ECH present, no clear SNI")
				} else {
					log.Tracef("TLS: SNI missing")
				}
				return "", false
			}

			// Validate the extracted SNI
			if !validateSNI(sni) {
				log.Tracef("TLS: Invalid SNI extracted: %q", sni)
				return "", false
			}

			return sni, true
		}
		i += 5 + recLen
	}
	log.Tracef("TLS: no handshake record")
	return "", false
}

func ParseTLSClientHelloBodySNI(ch []byte) (string, bool) {
	sni, _, _ := parseTLSClientHelloMeta(ch)
	if sni == "" {
		return "", false
	}

	// Validate the extracted SNI
	if !validateSNI(sni) {
		return "", false
	}

	return sni, true
}

func parseTLSClientHelloMeta(ch []byte) (string, bool, []string) {
	p := 0
	chLen := len(ch)

	// Version (2 bytes)
	if p+2 > chLen {
		return "", false, nil
	}
	p += 2

	// Random (32 bytes)
	if p+32 > chLen {
		return "", false, nil
	}
	p += 32

	// Session ID
	if p+1 > chLen {
		return "", false, nil
	}
	sidLen := int(ch[p])
	p++
	if p+sidLen > chLen {
		return "", false, nil
	}
	p += sidLen

	// Cipher suites
	if p+2 > chLen {
		return "", false, nil
	}
	csLen := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	if p+csLen > chLen {
		return "", false, nil
	}
	p += csLen

	// Compression methods
	if p+1 > chLen {
		return "", false, nil
	}
	cmLen := int(ch[p])
	p++
	if p+cmLen > chLen {
		return "", false, nil
	}
	p += cmLen

	// Extensions
	if p+2 > chLen {
		return "", false, nil
	}
	extLen := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	if extLen == 0 || p+extLen > chLen {
		return "", false, nil
	}

	exts := ch[p : p+extLen]
	extEnd := len(exts)

	var sni string
	var hasECH bool
	var alpns []string

	q := 0
	for q+4 <= extEnd {
		// Extension type (2 bytes)
		et := int(exts[q])<<8 | int(exts[q+1])
		// Extension length (2 bytes)
		el := int(exts[q+2])<<8 | int(exts[q+3])
		q += 4

		// Check bounds for extension data
		if el < 0 || q+el > extEnd {
			log.Tracef("TLS: Extension %d has invalid length %d", et, el)
			break
		}

		// Extension data
		ed := exts[q : q+el]

		switch et {
		case 0: // Server Name extension
			sniStr := extractSNIFromExtension(ed)
			if sniStr != "" {
				sni = sniStr
			}

		case 16: // ALPN extension
			alpns = extractALPNFromExtension(ed)

		default:
			if et == 0xfe0d || et == 0xfe0e || et == 0xfe0f {
				hasECH = true
			}
		}
		q += el
	}

	return sni, hasECH, alpns
}

func extractSNIFromExtension(ed []byte) string {
	if len(ed) < 2 {
		return ""
	}

	// Server name list length (2 bytes)
	listLen := int(ed[0])<<8 | int(ed[1])
	if listLen <= 0 || 2+listLen > len(ed) {
		log.Tracef("TLS: SNI list invalid length: %d, have %d bytes", listLen, len(ed))
		return ""
	}

	r := 2
	listEnd := 2 + listLen

	// Process server name entries
	for r+3 <= listEnd {
		// Name type (1 byte)
		nameType := ed[r]
		r++

		// Name length (2 bytes)
		if r+2 > listEnd {
			break
		}
		nameLen := int(ed[r])<<8 | int(ed[r+1])
		r += 2

		// Name data
		if nameLen <= 0 || r+nameLen > listEnd || r+nameLen > len(ed) {
			log.Tracef("TLS: SNI name invalid length: %d at position %d", nameLen, r)
			break
		}

		if nameType == 0 { // hostname type
			// Create a defensive copy of exactly nameLen bytes
			sniBytes := make([]byte, nameLen)
			copy(sniBytes, ed[r:r+nameLen])

			// Validate each byte before converting to string
			for i, b := range sniBytes {
				if !isValidSNIChar(b) {
					log.Tracef("TLS: Invalid byte 0x%02x at position %d in SNI", b, i)
					// Truncate at first invalid byte
					if i > 0 {
						return string(sniBytes[:i])
					}
					return ""
				}
			}

			return string(sniBytes)
		}

		r += nameLen
	}

	return ""
}

func extractALPNFromExtension(ed []byte) []string {
	var alpns []string

	if len(ed) < 2 {
		return alpns
	}

	// ALPN list length (2 bytes)
	listLen := int(ed[0])<<8 | int(ed[1])
	if listLen <= 0 || 2+listLen > len(ed) {
		return alpns
	}

	r := 2
	listEnd := 2 + listLen

	for r < listEnd {
		if r >= len(ed) {
			break
		}

		// Protocol name length (1 byte)
		protoLen := int(ed[r])
		r++

		if protoLen <= 0 || r+protoLen > listEnd || r+protoLen > len(ed) {
			break
		}

		// Protocol name
		alpns = append(alpns, string(ed[r:r+protoLen]))
		r += protoLen
	}

	return alpns
}
