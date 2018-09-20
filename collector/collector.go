package collector

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/pylls/steady"
)

// Output is the output function for the collector. Possible labels:
// evil, warning, unverified, and verified. Evil = network/relay bad, warning
// unclear who is doing what and potentially evil, unverified is data we got
// but cannot verify, and verified is verified data.
type Output func(label string, meta interface{}, format string, args ...interface{})

// Collector is a Steady collector.
type Collector struct {
	address   string
	conn      net.Conn
	frequency time.Duration
	delta     uint64
	Config    Config
	State     State
}

// State is the state kept by the collector.
type State struct {
	Time, Index uint64
}

type Block struct {
	BlockHeader steady.BlockHeader
	Payload     []byte
}

// NewCollector attempts to create a new collector connected to a relay.
func NewCollector(address string,
	config Config,
	frequency time.Duration,
	delta uint64) (*Collector, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return &Collector{
		address:   address,
		conn:      conn,
		frequency: frequency,
		delta:     delta,
		Config:    config,
	}, nil
}

// Close closes the underlying connection to the relay.
func (c *Collector) Close() {
	c.conn.Close()
}

// Proof is an audit path that proves membership to a root in a block, and
// the head of the block is part of the assessment.
type Proof struct {
	AssessmentID uint64
	EventIndex   int
	Path         [][]byte
}

// BlockHead is the minimal representation of a block for use with proofs.
type BlockHead struct {
	PayloadHash, RootHash, Root, IV, Signature []byte
	BlockID, Time, TreeSize                    uint64
}

// Unverified is the meta output description for unverifiable blocks and events.
type Unverified struct {
	AssessmentID uint64
	Description  string
}

const (
	// GreenAssessment is the overall assessment when everything checks out
	GreenAssessment = "ok"
	// YellowAssessment is the overall assessment for a warning
	YellowAssessment = "warning"
	// RedAssessment is the overall assessment when Steady detects something bad
	RedAssessment = "evil"

	// formatstrings
	assessmentFormat = "overall %s"
	timelyFormat     = "Block(s) delayed by %d seconds (policy timeout %d, delta %d)."
	sequenceFormat   = "Expected block with index %d."
	sizeFormat       = "Relay only returned %d bytes of valid blocks (policy space %d)"
	missedFormat     = "%d blocks overwritten since last read %d seconds ago. Reasonable? Relay space %d bytes."
	duplicateFormat  = "Got %d duplicate blocks from relay."
	invalidFormat    = "Got %d invalid (old index and/or invalid signature) blocks from relay."
	remainingFormat  = "Got %d remaining valid blocks that failed to be output"
)

// Finding describes a finding as part of an assessment. The description is a freetext description
// (see formatstrings above) while the label is one of three possible assessments.
type Finding struct {
	Label, Description string
}

// Assessment is the assessment made by Steady for each run of the collector loop.
type Assessment struct {
	// ID is the identifier of the assessment, linked to by all events.
	ID uint64
	// Overall is the overall assessment, see constants above.
	Overall string
	// Finding is one or more findings.
	Finding []Finding

	// Relay is the URL of the queried relay.
	Relay string
	// Time is the local time when performing the query.
	Time uint64
	// RequestIndex is the requested starting index in the query.
	RequestIndex uint64

	// TotalBlocks is the total number of blocks returned by the relay, where
	// TotalBlocks = ValidBlocks + InvalidBlocks + DuplicateBlocks.
	TotalBlocks uint64
	// ValidBlocks is the number of blocks with a valid signature and index.
	ValidBlocks uint64
	// InvalidBlocks is the number of blocks with an invalid signature and/or index.
	InvalidBlocks uint64
	// DuplicateBlocks is the number of duplicate (by index) blocks.
	DuplicateBlocks uint64

	// MissedBlocks is the number of missed blocks (see Description for details).
	MissedBlocks uint64

	// Blockheads is a map index->blockhead with the signed root of each block and
	// associated data needed to verify the signature on the root. Use together with
	// the path of each event from a valid block as a publicly verifiable proof of
	// event origin.
	Blockheads map[uint64]BlockHead
}

// CollectLoop is the main collect loop of the collector
func (c *Collector) CollectLoop(state State, close chan struct{}, out Output) {
	c.State = state
	ticker := time.NewTicker(c.frequency)
	defer ticker.Stop()
	for {
		select {
		case <-close:
			return
		case <-ticker.C:
		}

		blocks, err := c.readFromRelay()
		if err != nil {
			out("warning", "", err.Error())
			continue
		}

		// group blocks into sorted list of:
		// - blocks with valid signatures and correct index
		// - blocks without valid signature and/or correct index
		// - duplicate blocks (by index)
		valid, invalid, duplicate := c.group(blocks)
		var missed uint64
		if len(valid) > 0 {
			missed = valid[0].BlockHeader.Index - c.State.Index
		}
		assessment := &Assessment{
			ID:              uint64(time.Now().UnixNano()),
			Relay:           c.address,
			Time:            uint64(time.Now().Unix()),
			RequestIndex:    c.State.Index,
			TotalBlocks:     uint64(len(blocks)),
			ValidBlocks:     uint64(len(valid)),
			InvalidBlocks:   uint64(len(invalid)),
			DuplicateBlocks: uint64(len(duplicate)),
			Blockheads:      make(map[uint64]BlockHead),
			MissedBlocks:    missed,
		}

		// create assessment by looking for findings to base the overall assessment on
		c.assess(valid, assessment)

		// output all valid, invalid, and duplicate blocks with flags and link to assessment
		remaining := c.outputValid(valid, out, assessment)
		if len(remaining) > 0 {
			newFinding(RedAssessment, fmt.Sprintf(remainingFormat, len(remaining)), assessment)
			assessment.Overall = RedAssessment
		}

		c.outputBestEffort(remaining, "unverified", out, assessment)
		c.outputBestEffort(invalid, "invalid", out, assessment)
		c.outputBestEffort(duplicate, "duplicate", out, assessment)
		out("assessment", assessment, assessmentFormat, assessment.Overall)

		if len(valid) > 0 { // update state
			c.State.Index = valid[len(valid)-1].BlockHeader.Index + 1
			c.State.Time = valid[len(valid)-1].BlockHeader.Time
		}
	}
}

func (c *Collector) readFromRelay() (blocks []Block, err error) {
	// send request
	c.conn.Write([]byte{steady.WireVersion, steady.WireCmdRead})
	c.conn.Write(c.Config.Policy.ID)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, c.State.Index)
	c.conn.Write(tmp)

	// read number of blocks
	if err = readn(tmp, 8, c.conn); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint64(tmp)

	// get all blocks, one-by-one
	for i := uint64(0); i < count; i++ {
		// read block header
		buffer := make([]byte, steady.WireBlockHeaderSize)
		if err = readn(buffer, steady.WireBlockHeaderSize, c.conn); err != nil {
			return nil, err
		}
		bh, err := steady.DecodeBlockHeader(buffer, c.Config.Policy)
		if err != nil {
			return nil, err
		}
		// read payload
		buffer = make([]byte, int(bh.LenCur-steady.WireBlockHeaderSize))
		if err = readn(buffer, int(bh.LenCur-steady.WireBlockHeaderSize), c.conn); err != nil {
			return nil, err
		}
		blocks = append(blocks, Block{
			BlockHeader: bh,
			Payload:     buffer,
		})
	}
	return
}

func readn(dst []byte, n int, conn net.Conn) error {
	l, err := io.ReadFull(conn, dst)
	if err != nil {
		return fmt.Errorf("failed to read from conn: %v", err)
	}
	if l < n {
		return fmt.Errorf("read %d bytes from conn, expected %d", l, n)
	}
	return nil
}

func (c *Collector) group(blocks []Block) (valid, invalid, duplicate []Block) {
	valid = make([]Block, 0, len(blocks)) // most of the time, all is valid
	invalid = make([]Block, 0)
	duplicate = make([]Block, 0)

	// sort blocks by index, such that our resulting maps are also sorted
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].BlockHeader.Index < blocks[j].BlockHeader.Index })

	duplicates := make(map[uint64]bool)
	for i := 0; i < len(blocks); i++ {
		if _, exists := duplicates[blocks[i].BlockHeader.Index]; exists {
			duplicate = append(duplicate, blocks[i])
			continue
		}
		if blocks[i].BlockHeader.Index >= c.State.Index {
			valid = append(valid, blocks[i])
		} else {
			invalid = append(invalid, blocks[i])
		}
		duplicates[blocks[i].BlockHeader.Index] = true
	}

	return
}

// determine overall assessment and description, gives context to "missed blocks"
// we have exactly threee _possible_ cases:
// - len(valid) = 0
// - len(valid) > 0 && valid[0].Index = state.Index
// - len(valid) > 0 && valid[0].Index != state.Index
// for each case we have specific checks to detect deletion
func (c *Collector) assess(valid []Block, a *Assessment) {
	if len(valid) == 0 {
		// timely check relative to time in state
		c.checkTimely(c.State.Time, a)
	} else if valid[0].BlockHeader.Index == c.State.Index {
		// timely check relative to last valid block
		c.checkTimely(valid[len(valid)-1].BlockHeader.Time, a)
		// sequence check
		c.checkSequence(valid, a)
	} else {
		// timely check relative to last valid block
		c.checkTimely(valid[len(valid)-1].BlockHeader.Time, a)
		// sequence check
		c.checkSequence(valid, a)
		// size check
		c.checkSize(valid, a)
		// by definition we have missing blocks
		newFinding(YellowAssessment,
			fmt.Sprintf(missedFormat, a.MissedBlocks,
				a.Time-c.State.Time, c.Config.Policy.Space), a)
	}

	// duplicate blocks
	if a.DuplicateBlocks > 0 {
		newFinding(RedAssessment,
			fmt.Sprintf(duplicateFormat, a.DuplicateBlocks), a)
	}
	// invalid blocks
	if a.InvalidBlocks > 0 {
		newFinding(RedAssessment,
			fmt.Sprintf(invalidFormat, a.InvalidBlocks), a)
	}

	// set overall assessment
	if len(a.Finding) == 0 {
		a.Overall = GreenAssessment
	} else {
		a.Overall = YellowAssessment // yellow if no red
		for i := 0; i < len(a.Finding); i++ {
			if a.Finding[i].Label == RedAssessment {
				a.Overall = RedAssessment
				break // one red is enough
			}
		}
	}
}

func (c *Collector) checkTimely(then uint64, a *Assessment) {
	delay := a.Time - then
	if delay > c.Config.Policy.Timeout+c.delta {
		newFinding(YellowAssessment,
			fmt.Sprintf(timelyFormat, delay, c.Config.Policy.Timeout, c.delta), a)
	}
}

func (c *Collector) checkSequence(blocks []Block, a *Assessment) {
	prev := blocks[0]
	for i := 1; i < len(blocks); i++ {
		if blocks[i].BlockHeader.Index != prev.BlockHeader.Index+1 {
			newFinding(RedAssessment, fmt.Sprintf(sequenceFormat, prev.BlockHeader.Index+1), a)
			a.MissedBlocks++ // FIXME: include or not?
		}
		prev = blocks[i]
	}
}

func (c *Collector) checkSize(blocks []Block, a *Assessment) {
	var size uint64
	for _, b := range blocks {
		size += b.BlockHeader.LenCur
	}
	if size+blocks[0].BlockHeader.LenPrev <= c.Config.Policy.Space {
		newFinding(RedAssessment, fmt.Sprintf(sizeFormat, size, c.Config.Policy.Space), a)
	}
}

func newFinding(label, desc string, a *Assessment) {
	a.Finding = append(a.Finding, Finding{
		Label:       label,
		Description: desc,
	})
}

func (c *Collector) outputValid(ok []Block, out Output, a *Assessment) []Block {
	remaining := make([]Block, 0)

	for i := 0; i < len(ok); i++ {
		events, iv, err := steady.DecodeBlockPayload(ok[i].Payload,
			c.Config.Pub, c.Config.Priv, c.Config.Policy, ok[i].BlockHeader)
		if err != nil {
			remaining = append(remaining, ok[i])
			a.MissedBlocks++
			continue
		}
		a.Blockheads[ok[i].BlockHeader.Index] = BlockHead{
			BlockID:     ok[i].BlockHeader.Index,
			PayloadHash: ok[i].BlockHeader.PayloadHash,
			RootHash:    ok[i].BlockHeader.RootHash,
			Root:        steady.MerkleTreeHash(events),
			IV:          iv,
			Signature:   ok[i].BlockHeader.Signature,
			Time:        ok[i].BlockHeader.Time,
			TreeSize:    uint64(len(events)),
		}

		if events != nil {
			for j := 0; j < len(events); j++ { // FIXME: make this concurrent
				out("verified", Proof{
					AssessmentID: a.ID,
					EventIndex:   j,
					Path:         steady.AuditPath(j, events), // FIXME: make non-recursive
				}, string(events[j]))
			}
		}
	}

	return remaining
}

func (c *Collector) outputBestEffort(b []Block, label string, out Output, a *Assessment) {
	for i := 0; i < len(b); i++ {
		events, _, err := steady.DecodeBlockPayload(b[i].Payload,
			c.Config.Pub, c.Config.Priv, c.Config.Policy, b[i].BlockHeader)
		if err != nil {
			out(label, Unverified{
				AssessmentID: a.ID,
				Description:  fmt.Sprintf("failed to decode block: %s", err),
			}, string(b[i].Payload))
			continue
		}
		if events != nil {
			for j := 0; j < len(events); j++ {
				out(label,
					Unverified{
						AssessmentID: a.ID,
						Description:  "",
					}, string(events[j]))
			}
		}
	}
}
