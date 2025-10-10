package mangle

import (
	"encoding/binary"
)

func recalcTCPChecksum(pkt []byte, ipVersion int) {
	var tcpStart int
	var pseudoHeader []byte

	if ipVersion == 4 {
		ihl := int((pkt[0] & 0x0f) << 2)
		tcpStart = ihl
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		tcpLen := totalLen - uint16(ihl)

		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:4], pkt[12:16])
		copy(pseudoHeader[4:8], pkt[16:20])
		pseudoHeader[9] = 6
		binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)
	} else {
		tcpStart = 40
		tcpLen := binary.BigEndian.Uint16(pkt[4:6])

		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:16], pkt[8:24])
		copy(pseudoHeader[16:32], pkt[24:40])
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(tcpLen))
		pseudoHeader[39] = 6
	}

	pkt[tcpStart+16] = 0
	pkt[tcpStart+17] = 0

	checksum := calculateChecksum(pseudoHeader)
	tcpData := pkt[tcpStart : tcpStart+int(binary.BigEndian.Uint16(pkt[4:6]))]
	if ipVersion == 4 {
		totalLen := binary.BigEndian.Uint16(pkt[2:4])
		ihl := int((pkt[0] & 0x0f) << 2)
		tcpData = pkt[tcpStart : tcpStart+int(totalLen)-ihl]
	}
	checksum = calculateChecksumAdd(checksum, tcpData)
	binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], ^checksum)
}

func extractTCPPayload(pkt []byte, ipVersion int) ([]byte, int, int) {
	var ipHdrLen, tcpStart int

	if ipVersion == 4 {
		ipHdrLen = int((pkt[0] & 0x0f) << 2)
		tcpStart = ipHdrLen
	} else {
		ipHdrLen = 40
		tcpStart = 40
	}

	if len(pkt) <= tcpStart+12 {
		return nil, 0, 0
	}

	tcpHdrLen := int((pkt[tcpStart+12] >> 4) << 2)
	payloadStart := tcpStart + tcpHdrLen

	if len(pkt) <= payloadStart {
		return nil, tcpStart, tcpHdrLen
	}

	return pkt[payloadStart:], tcpStart, tcpHdrLen
}
