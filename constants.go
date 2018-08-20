package steady

import (
	"github.com/pylls/steady/lc"
)

const (
	SetupFilename       = "%s.device"
	DeviceStateFilename = "%s.state"
	CollectorFilename   = "%s.collector"

	WireVersion        = 0x42
	WireIdentifierSize = 32

	// commands
	WireCmdStatus = 0x0
	WireCmdSetup  = 0x1
	WireCmdRead   = 0x2
	WireCmdWrite  = 0x3

	WireTrue    = 0x1
	WireFalse   = 0x0
	WireMore    = 0xA
	WireAuthErr = 0xF

	WirePolicySize      = WireIdentifierSize + lc.VericationKeySize + lc.PublicKeySize + 3*8 + lc.SignatureSize
	WireBlockHeaderSize = 4*8 + 3*lc.HashOutputLen + lc.SignatureSize
	WireAuthSize        = lc.HashOutputLen

	MaxBlockSize = 104857600 // 100 MiB
)
