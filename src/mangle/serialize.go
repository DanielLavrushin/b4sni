package mangle

import (
	"encoding/binary"
)

func recalcIPv4Checksum(pkt []byte) {
	if len(pkt) < 20 {
		return
	}

	ihl := int((pkt[0] & 0x0f) << 2)
	if ihl < 20 || len(pkt) < ihl {
		return
	}

	pkt[10] = 0
	pkt[11] = 0

	checksum := calculateChecksum(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], ^checksum)
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32

	length := len(data)
	index := 0

	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}

	if length > 0 {
		sum += uint32(data[index]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum)
}

func calculateChecksumAdd(initial uint16, data []byte) uint16 {
	sum := uint32(initial)

	length := len(data)
	index := 0

	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}

	if length > 0 {
		sum += uint32(data[index]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum)
}
