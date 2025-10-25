package sni

import (
	"github.com/daniellavrushin/b4sni/log"
)

const (
	tlsContentTypeHandshake uint8 = 22
	tlsHandshakeClientHello uint8 = 1
)

const (
	tlsExtServerName uint16 = 0
)

type parseErr string

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
