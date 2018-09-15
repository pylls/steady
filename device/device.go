/*
 * Stub for a Steady device in Go, only used to make the device config,
 * please see the C implementation of the device for now.
 */
package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

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

// Log (on device)
func (d *Device) Log(msg string) error {
	if len(msg) > 65535 {
		return fmt.Errorf("max message length is %d, got %d", 65535, len(msg))
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	if !d.open {
		return fmt.Errorf("device is closed")
	}
	d.chanLog <- msg
	return nil
}

// Close flushes the device, closes connection to the relay, and frees all
// resources. Afterwards the device can no longer be used to log.
func (d *Device) Close() error {
	// get lock, prevent others from logging more
	d.lock.Lock()
	defer d.lock.Unlock()
	d.open = false
	// close log chan, give close msg
	close(d.chanLog)
	d.chanClose <- true
	d.wait.Wait()
	return nil
}

// estimating memory usage: flushSize*(blockBufferNum+1)
// LoadDevice loads a device from the given fs path
func LoadDevice(path, server, token string, encrypt, compress bool,
	flushSize int, blockBufferNum int) (*Device, error) {
	// atempt to load from disk
	device, err := readDevice(fmt.Sprintf(steady.SetupFilename, path))
	if err != nil {
		return nil, err
	}
	state, err := readDeviceState(fmt.Sprintf(steady.DeviceStateFilename, path))
	if err != nil { // assume error means we don't have any state
		state = new(DeviceState)
		state.NextIndex = 0
		state.LenPrev = 0
		state.TimePrev = device.Policy.Time
	}

	// attempt to connect to relay and check status
	device.conn, err = net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	status, header, err := checkStatus(device.conn, device.Policy.ID, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %v", err)
	}
	if status[0] == steady.WireFalse {
		return nil, fmt.Errorf("device is not setup at relay")
	}
	if status[0] == steady.WireTrue && state.NextIndex != 0 {
		return nil, fmt.Errorf("relay returned inconsistent state on status check")
	}
	if status[0] == steady.WireMore {
		bh, err := steady.DecodeBlockHeader(header, device.Policy)
		if err != nil {
			return nil, fmt.Errorf("relay returned an invalid block header on status check: %v", err)
		}
		if bh.Index+1 < state.NextIndex {
			return nil, fmt.Errorf("relay returned old block header on status check, possible attack")
		}
		state.NextIndex = bh.Index + 1
		state.LenPrev = bh.LenCur
		state.TimePrev = bh.Time
	}

	// setup channels and spawn worker
	device.chanClose = make(chan bool, 1)
	device.chanLog = make(chan string, flushSize/512) // Note: assuming 512 bytes average messages
	device.open = true
	device.wait.Add(1)
	go device.loggingThread(fmt.Sprintf(steady.DeviceStateFilename, path), state, encrypt, compress,
		flushSize, blockBufferNum, token)

	return device, nil
}

func (d *Device) loggingThread(stateFile string, state *DeviceState,
	encrypt, compress bool, flushSize, blockBufferNum int, token string) {
	timer := time.After(time.Duration(int64(d.Policy.Timeout)-
		(time.Now().Unix()-int64(state.TimePrev))) * time.Second)
	var buffer [][]byte
	var bufferSize int

	// async sender of blocks
	blockChan := make(chan []byte, blockBufferNum)
	var waitSender sync.WaitGroup
	waitSender.Add(1)
	go d.sender(blockChan, &waitSender, token)

	for {
		select {
		case <-timer: // timeout, send a block
			d.makeBlock(buffer, state, encrypt, compress, blockChan)
			buffer = make([][]byte, 0)
			bufferSize = 0
			timer = time.After(time.Duration(d.Policy.Timeout) * time.Second)
		case data := <-d.chanLog: // buffer log data
			// TODO: we should drop here if it makes sense to, such that we can keep statistics on drops
			// if we need to drop or not is simple: check length of blockChan
			buffer = append(buffer, []byte(data))
			bufferSize += len(data) + 2 // for uint_16 length encoding
			if bufferSize >= flushSize {
				d.makeBlock(buffer, state, encrypt, compress, blockChan)
				buffer = make([][]byte, 0)
				bufferSize = 0
				timer = time.After(time.Duration(d.Policy.Timeout) * time.Second)
			}
		case <-d.chanClose: // signal to close
			for data := range d.chanLog { // drain the log channel
				buffer = append(buffer, []byte(data))
				bufferSize += len(data) + 2 // for uint_16 length encoding
			}
			if bufferSize > 0 { // send any data if we have any
				d.makeBlock(buffer, state, encrypt, compress, blockChan)
				buffer = make([][]byte, 0)
				bufferSize = 0
				timer = time.After(time.Duration(d.Policy.Timeout) * time.Second)
			}
			close(blockChan)                   // this will make sender eventually wrap up
			waitSender.Wait()                  // so we wait for sender to finish sending
			writeDeviceState(state, stateFile) // attempt to save state, ignore any error
			d.wait.Done()                      // all good, signal done
			return
		}
	}
}

func (d *Device) makeBlock(buffer [][]byte, s *DeviceState, encrypt, compress bool,
	blockChan chan []byte) {
	t := uint64(time.Now().Unix())
	log.Printf("index is %d", s.NextIndex)
	block, err := steady.MakeEncodedBlock(s.NextIndex, s.LenPrev, t,
		encrypt, compress, d.Policy, buffer, d.Sk)
	if err != nil {
		panic(fmt.Sprintf("error on MakeEncodeBlock, should not happen: %v", err))
	}
	s.NextIndex++
	s.LenPrev = uint64(len(block))
	s.TimePrev = t

	blockChan <- block
}

func (d *Device) sender(in chan []byte, wait *sync.WaitGroup, token string) {
	defer wait.Done()
	buf := make([]byte, 8+steady.WireAuthSize)
	numBlocks := make([]byte, 2)
	binary.BigEndian.PutUint16(numBlocks, 1)
	for {
		block, open := <-in
		if !open {
			return
		}
		for { // hammer until sent
			d.conn.Write([]byte{steady.WireVersion, steady.WireCmdWrite}) // we want to write a block...
			d.conn.Write(d.Policy.ID)                                     // ...to this policy...
			d.conn.Write(numBlocks)                                       // ...only one block...
			d.conn.Write(block)                                           // ...and here's the block

			l, err := d.conn.Read(buf)
			if err != nil {
				log.Fatalf("failed to read reply: %v", err) // FIXME, prob continue?
			}
			if l != 8+steady.WireAuthSize {
				continue
			}
			if !bytes.Equal(block[:8], buf[:8]) ||
				!bytes.Equal(buf[8:], lc.Khash([]byte(token), []byte("write"), d.Policy.ID, block[:8])) {
				continue
			}

			break
		}
	}
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

func readDeviceState(filename string) (*DeviceState, error) {
	var state DeviceState
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("state too small, expected 24 bytes, read %d", len(data))
	}
	state.NextIndex = binary.BigEndian.Uint64(data[:8])
	state.TimePrev = binary.BigEndian.Uint64(data[8:16])
	state.LenPrev = binary.BigEndian.Uint64(data[16:24])
	return &state, nil
}

func writeDeviceState(state *DeviceState, filename string) error {
	var buf [24]byte
	binary.BigEndian.PutUint64(buf[:], state.NextIndex)
	binary.BigEndian.PutUint64(buf[8:], state.TimePrev)
	binary.BigEndian.PutUint64(buf[16:], state.LenPrev)
	return ioutil.WriteFile(filename, buf[:], 0600)
}
