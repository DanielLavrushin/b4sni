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

func ParseTLSClientHelloSNI(b []byte) (string, bool) {
	log.Tracef("TCP Payload=%v", len(b))
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
	return sni, true
}

func parseTLSClientHelloMeta(ch []byte) (string, bool, []string) {
	p := 0
	if p+2 > len(ch) {
		return "", false, nil
	}
	p += 2
	if p+32 > len(ch) {
		return "", false, nil
	}
	p += 32
	if p+1 > len(ch) {
		return "", false, nil
	}
	sidLen := int(ch[p])
	p++
	if p+sidLen > len(ch) {
		return "", false, nil
	}
	p += sidLen
	if p+2 > len(ch) {
		return "", false, nil
	}
	csLen := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	if p+csLen > len(ch) {
		return "", false, nil
	}
	p += csLen
	if p+1 > len(ch) {
		return "", false, nil
	}
	cmLen := int(ch[p])
	p++
	if p+cmLen > len(ch) {
		return "", false, nil
	}
	p += cmLen
	if p+2 > len(ch) {
		return "", false, nil
	}
	extLen := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	if extLen == 0 || p+extLen > len(ch) {
		return "", false, nil
	}
	exts := ch[p : p+extLen]

	var sni string
	var hasECH bool
	var alpns []string

	q := 0
	for q+4 <= len(exts) {
		et := int(exts[q])<<8 | int(exts[q+1])
		el := int(exts[q+2])<<8 | int(exts[q+3])
		q += 4
		if q+el > len(exts) {
			break
		}
		ed := exts[q : q+el]

		switch et {
		case 0:
			if len(ed) >= 2 {
				listLen := int(ed[0])<<8 | int(ed[1])
				if 2+listLen <= len(ed) && listLen >= 3 {
					r := 2
					if r+3 <= 2+listLen {
						nt := ed[r]
						nl := int(ed[r+1])<<8 | int(ed[r+2])
						r += 3
						if nt == 0 && r+nl <= 2+listLen && nl > 0 {
							sni = string(ed[r : r+nl])
						}
					}
				}
			}
		case 16:
			if len(ed) >= 2 {
				l := int(ed[0])<<8 | int(ed[1])
				if 2+l <= len(ed) {
					r := 2
					for r < 2+l {
						if r >= 2+l {
							break
						}
						ln := int(ed[r])
						r++
						if r+ln > 2+l {
							break
						}
						alpns = append(alpns, string(ed[r:r+ln]))
						r += ln
					}
				}
			}
		default:
			if et == 0xfe0d || et == 0xfe0e || et == 0xfe0f {
				hasECH = true
			}
		}
		q += el
	}
	return sni, hasECH, alpns
}
