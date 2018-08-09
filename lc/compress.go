package lc

import (
	"bytes"
	"io"

	"github.com/pierrec/lz4"
)

func Compress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	writer := lz4.NewWriter(buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Decompress(in []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	reader := lz4.NewReader(bytes.NewReader(in))
	_, err := io.Copy(buf, reader)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
