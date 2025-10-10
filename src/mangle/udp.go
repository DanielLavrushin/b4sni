package mangle

import (
	"encoding/binary"
)

func recalcUDPChecksum(pkt []byte, ipVersion int) {
	var udpStart int
	var pseudoHeader []byte

	if ipVersion == 4 {
		ihl := int((pkt[0] & 0x0f) << 2)
		udpStart = ihl
		udpLen := binary.BigEndian.Uint16(pkt[udpStart+4 : udpStart+6])

		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:4], pkt[12:16])
		copy(pseudoHeader[4:8], pkt[16:20])
		pseudoHeader[9] = 17
		binary.BigEndian.PutUint16(pseudoHeader[10:12], udpLen)
	} else {
		udpStart = 40
		udpLen := binary.BigEndian.Uint16(pkt[4:6])

		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:16], pkt[8:24])
		copy(pseudoHeader[16:32], pkt[24:40])
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(udpLen))
		pseudoHeader[39] = 17
	}

	pkt[udpStart+6] = 0
	pkt[udpStart+7] = 0

	checksum := calculateChecksum(pseudoHeader)
	udpData := pkt[udpStart:]
	if ipVersion == 4 {
		udpLen := binary.BigEndian.Uint16(pkt[udpStart+4 : udpStart+6])
		udpData = pkt[udpStart : udpStart+int(udpLen)]
	}
	checksum = calculateChecksumAdd(checksum, udpData)
	if checksum == 0xffff {
		checksum = 0
	}
	binary.BigEndian.PutUint16(pkt[udpStart+6:udpStart+8], ^checksum)
}

func extractUDPPayload(pkt []byte, ipVersion int) ([]byte, int) {
	var ipHdrLen, udpStart int

	if ipVersion == 4 {
		ipHdrLen = int((pkt[0] & 0x0f) << 2)
		udpStart = ipHdrLen
	} else {
		ipHdrLen = 40
		udpStart = 40
	}

	if len(pkt) <= udpStart+8 {
		return nil, 0
	}

	return pkt[udpStart+8:], udpStart
}
