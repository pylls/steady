/*
 * Stub for a Steady device in Go, only used to make the device config,
 * please see the C implementation of the device for now.
 */
package device

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

type Device struct {
	Sk     []byte
	Policy steady.Policy
	// never written or read from disk below
	conn      net.Conn
	testing   bool
	chanClose chan bool
	chanLog   chan string
	lock      sync.Mutex
	open      bool
	wait      sync.WaitGroup
}

type DeviceState struct {
	NextIndex, TimePrev, LenPrev uint64
}

func MakeDevice(sk, vk, pub []byte,
	timeout, space, time uint64,
	path, server, token string) (*steady.Policy, error) {
	if _, err := os.Stat(fmt.Sprintf(steady.SetupFilename, path)); !os.IsNotExist(err) {
		return nil, fmt.Errorf("config file already exists at path "+steady.SetupFilename, path)
	}
	if _, err := os.Stat(fmt.Sprintf(steady.DeviceStateFilename, path)); !os.IsNotExist(err) {
		return nil, fmt.Errorf("state file already exists at path "+steady.DeviceStateFilename, path)
	}

	// attempt to connect to relay
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// attempt to setup new policy and then check status
	p := steady.MakePolicy(sk, vk, pub, timeout, space, time)
	conn.Write([]byte{steady.WireVersion, steady.WireCmdSetup})
	encodedPolicy := steady.EncodePolicy(p)
	conn.Write(encodedPolicy)
	conn.Write(lc.Khash([]byte(token), []byte("setup"), encodedPolicy))
	status, _, err := checkStatus(conn, p.ID, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %v", err)
	}
	if status[0] != steady.WireTrue {
		return nil, fmt.Errorf("failed to setup, wrong relay?")
	}

	return &p, writeDevice(&Device{
		Sk:     sk,
		Policy: p,
	}, fmt.Sprintf(steady.SetupFilename, path))
}

func writeDevice(device *Device, filename string) error {
	buf := bytes.NewBuffer(nil)
	buf.Write(device.Sk)
	buf.Write(steady.EncodePolicy(device.Policy))
	return ioutil.WriteFile(filename, buf.Bytes(), 0400)
}

func readDevice(filename string) (*Device, error) {
	var device Device
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) < steady.WirePolicySize+lc.SigningKeySize {
		return nil, fmt.Errorf("data for device on disk too small")
	}
	device.Sk = data[:lc.SigningKeySize]
	device.Policy, err = steady.DecodePolicy(data[lc.SigningKeySize:])
	return &device, err
}

func checkStatus(conn net.Conn, id []byte, token string) (status, header []byte, err error) {
	buf := make([]byte, 1)
	conn.Write([]byte{steady.WireVersion, steady.WireCmdStatus})
	conn.Write(id)
	conn.Write(lc.Khash([]byte(token), []byte("status"), id))
	l, err := conn.Read(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read reply to status check: %v", err)
	}
	if l < 1 {
		return nil, nil, fmt.Errorf("failed to read reply to status check")
	}
	if buf[0] == steady.WireMore {
		header = make([]byte, steady.WireBlockHeaderSize)
		l, err = conn.Read(header)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read block header after status check: %v", err)
		}
		if l < steady.WireBlockHeaderSize {
			return nil, nil, fmt.Errorf("too short reply to status check")
		}
	}
	return buf, header, nil
}
