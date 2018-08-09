package collector

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/pylls/steady"
	"github.com/pylls/steady/lc"
)

type Config struct {
	Pub, Priv, Vk []byte
	Policy        steady.Policy
}

func WriteCollectorConfig(c *Config, filename string) error {
	buf := bytes.NewBuffer(nil)
	buf.Write(c.Pub)
	buf.Write(c.Priv)
	buf.Write(c.Vk)
	buf.Write(steady.EncodePolicy(c.Policy))
	return ioutil.WriteFile(filename, buf.Bytes(), 0400)
}

func ReadCollectorConfig(filename string) (*Config, error) {
	var c Config
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) < steady.WirePolicySize+lc.PublicKeySize+lc.PrivategKeySize+lc.VericationKeySize {
		return nil, fmt.Errorf("data for collector config on disk too small")
	}
	c.Pub = data[:lc.PublicKeySize]
	c.Priv = data[lc.PublicKeySize : lc.PublicKeySize+lc.PrivategKeySize]
	c.Vk = data[lc.PublicKeySize+lc.PrivategKeySize : lc.PublicKeySize+lc.PrivategKeySize+lc.VericationKeySize]
	c.Policy, err = steady.DecodePolicy(data[lc.PublicKeySize+lc.PrivategKeySize+lc.VericationKeySize:])
	return &c, err
}
