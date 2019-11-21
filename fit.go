package intelfit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type FIT struct {
	Offset  uint32
	Mask    uint64
	Header  FitHeader
	Entries []FitEntry
}
type FitHeader struct {
	Signature string
	FitEntry
}
type FitEntry struct {
	Address           uint64
	Size              uint32
	Reserved          byte
	Version           uint16
	Type              FITType
	TypeString        string
	ChecksumAvailable bool
	Checksum          byte
}

type binaryFitEntry struct {
	Address         uint64
	Size            [3]byte
	Reserved        byte
	Version         uint16
	ChecksumAndType byte
	Checksum        byte
}

type FITType int

const (
	FIT_HEADER FITType = iota
	MICROCODE_UPDATE
	STARTUP_AC_MODULE
	BIOS_STARTUP_MODULE = iota + 0x07
	TPM_POLICY
	BIOS_POLICY
	TXT_POLICY
	KEY_MANIFEST
	BOOT_POLICY
	CSE_SECURE_BOOT         = 0x10
	FEATURE_POLICY_DELIVERY = 0x2D
	JMP_DEBUG               = 0x2F
	OEM_RESERVED_START      = 0x30
	OEM_RESERVED_END        = 0x70
	SKIP                    = 0x7F
)

func (s FITType) String() string {
	switch s {
	case FIT_HEADER:
		return "FIT_HEADER"
	case MICROCODE_UPDATE:
		return "MICROCODE_UPDATE"
	case STARTUP_AC_MODULE:
		return "STARTUP_AC_MODULE"
	case BIOS_STARTUP_MODULE:
		return "BIOS_STARTUP_MODULE"
	case TPM_POLICY:
		return "TPM_POLICY"
	case KEY_MANIFEST:
		return "KEY_MANIFEST"
	case BOOT_POLICY:
		return "BOOT_POLICY"
	case CSE_SECURE_BOOT:
		return "CSE_SECURE_BOOT"
	case FEATURE_POLICY_DELIVERY:
		return "FEATURE_POLICY_DELIVERY"
	case JMP_DEBUG:
		return "JMP_DEBUG"
	default:
		if s >= OEM_RESERVED_START && s <= OEM_RESERVED_END {
			return "OEM_RESERVED"
		}
		return "INTEL_RESERVED"
	}
}

func ParseFITEntry(FITReader io.Reader, next *FitEntry, mask uint64) {
	binaryFitEntry := binaryFitEntry{}
	binary.Read(FITReader, binary.LittleEndian, &binaryFitEntry)
	//extend to 32 bit value
	size := append(binaryFitEntry.Size[:], 0x00)
	next.Address = binaryFitEntry.Address - mask
	next.Size = binary.LittleEndian.Uint32(size)
	next.Reserved = binaryFitEntry.Reserved
	next.Version = binaryFitEntry.Version
	next.Type = FITType(binaryFitEntry.ChecksumAndType) & 0x7F
	next.TypeString = FITType.String(next.Type)
	next.ChecksumAvailable = (binaryFitEntry.ChecksumAndType & 0x80) != 0
	next.Checksum = binaryFitEntry.Checksum
}

func ParseFIT(firmwareBytes []byte) (*FIT, error) {
	fit := FIT{}

	if len(firmwareBytes) < 0x40 {
		return nil, fmt.Errorf("firmwarebytes not long enough for reading FIT pointer")
	}

	address := binary.LittleEndian.Uint32(firmwareBytes[len(firmwareBytes)-0x40:])
	fit.Mask = uint64(0xFFFFFFFF) - uint64(len(firmwareBytes)) + 1
	address = uint32(uint64(address) - fit.Mask)
	if address > uint32(len(firmwareBytes)) {
		return nil, fmt.Errorf("fit outside of flashimage")
	}
	fit.Offset = address

	FITReader := bytes.NewReader(firmwareBytes[address:])

	sig := string(firmwareBytes[address : address+8])
	if sig != "_FIT_   " {
		return nil, fmt.Errorf("header signature does not fit: %s", sig)
	}
	fit.Header.Signature = sig

	//Overwritten when header was read
	numEntries := 1
	for i := 0; i <= numEntries; i++ {
		next := FitEntry{}
		ParseFITEntry(FITReader, &next, fit.Mask)

		//Header comes first
		if i == 0 {
			if next.Type != FIT_HEADER {
				return nil, fmt.Errorf("fit does not begin with a header entry")
			}

			if next.Size*16 > uint32(len(firmwareBytes))-address {
				return nil, fmt.Errorf("fit does not fit into firmware image")
			}

			numEntries = int(next.Size)
			fit.Header.FitEntry = next
		} else {
			fit.Entries = append(fit.Entries, next)
		}
	}
	return &fit, nil
}
