package intelft

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type FIT struct {
	Offset uint32
	Header FITHeader
	Entries []FitEntry
}

type FITHeader struct {
	Signature [8]byte
	Length uint32
	Unknown [4]byte
}

type FitEntry struct {
	Address uint64
	Size uint32
	Reserved byte
	Version uint16
	Type byte
	ChecksumAvailable byte
	Checksum byte
}

const (
	FIT_HEADER = iota
	MICROCODE_UPDATE
	STARTUP_AC_MODULE
	BIOS_STARTUP_MODULE = 0x07
	TPM_POLICY
	BIOS_POLICY
	TXT_POLICY
	KEY_MANIFEST
	BOOT_POLICY
	CSE_SECURE_BOOT = 0x10
	FEATURE_POLICY_DELIVERY = 0x2D
	JMP_DEBUG = 0x2F
	OEM_RESERVED_START = 0x30
	OEM_RESERVED_END = 0x70
	SKIP = 0x7F

)

	func ParseFIT(firmwareBytes []byte) (*FIT, error) {
	var address uint32
	fit := FIT{}

	//TODO Test
	if (len(firmwareBytes) < 0x40){
		return nil, fmt.Errorf("Firmwarebytes not long enough for reading FIT pointer..")
	}

	directoryReader := bytes.NewReader(firmwareBytes[len(firmwareBytes)-0x40:])

	if err := binary.Read(directoryReader, binary.LittleEndian, &address); err != nil {
		return nil, fmt.Errorf("Error creating reader for fit pointer..")
	}

	//TODO Tet
	mask := 0xFFFFFFFF - len(firmwareBytes) + 1;

	address = address ^ uint32(mask);
	//TODO Test
	if address > uint32(len(firmwareBytes)) {
		return nil, fmt.Errorf("Firmwarebytes not long enough for reading FIT..")
	}

	fit.Offset = address;

	FITReader := bytes.NewReader(firmwareBytes[address:])

	if err := binary.Read(FITReader, binary.LittleEndian, &fit.Header); err != nil {
		//todo mimimi
	}

	if string(fit.Header.Signature[:]) != "_FIT_   "{
		//TODO test
		//TODO mimimi
		log.Print("Header does not fit")
		return &fit, nil
	}

	enc := json.NewEncoder(os.Stdout)
	for entryID := uint32(1); entryID < fit.Header.Length; entryID++ {
		binaryFitEntry := struct {
			Address uint64
			Size [3]byte
			Reserved byte
			Version uint16
			ChecksumAndType byte
			Checksum byte
		}{}
		binary.Read(FITReader, binary.LittleEndian, &binaryFitEntry)
		//extend to 32 bit value
		size := append(binaryFitEntry.Size[:], 0x00)
		next := FitEntry{
			Address:           binaryFitEntry.Address - uint64(mask),
			Size:              binary.LittleEndian.Uint32(size),
			Reserved:          binaryFitEntry.Reserved,
			Version:           binaryFitEntry.Version,
			Type:              binaryFitEntry.ChecksumAndType & 0x7F,
			ChecksumAvailable: binaryFitEntry.ChecksumAndType & 0x80,
			Checksum:          binaryFitEntry.Checksum,
		}
		enc.Encode(next)
	}

	return &fit, nil
}
//TODO move to parse fit entry