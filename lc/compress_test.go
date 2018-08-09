package lc

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompressDecompress(t *testing.T) {
	data := []byte("some data to compressaaaaaaaaaaaaaaaaaaaaaaa")
	c, err := Compress(data)
	assert.Nil(t, err, "got error when compressing data")
	d, err := Decompress(c)
	assert.Nil(t, err, "got error when decompressing data")
	assert.True(t, bytes.Equal(data, d), "decompressed data differs with compressed")

}
