package parser

import (
	"fmt"
	"testing"

	"github.com/gotestyourself/gotestyourself/assert"
)

var pemTests = []struct {
	file string
}{
	// {"letsencrypt-public.pem"},
	{"ec384-public.pem"},
	// {"ec384-private.pem"},
}

func TestParsePemFiles(t *testing.T) {
	for _, test := range pemTests {
		t.Run(test.file, func(t *testing.T) {
			enc, err := ParsePemFile("./testdata/" + test.file)
			assert.NilError(t, err)
			fmt.Println(enc)
		})
	}
}

var fieldParsingTests = []struct {
	name            string
	octets          []byte
	expectedTag     int
	expectedLength  int
	expectedContent string
}{
	{
		"BIT STRING",
		[]byte{0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0},
		3,
		4,
		"011011100101110111",
	},
	{
		"BIT STRING padded",
		[]byte{0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0},
		3,
		4,
		"011011100101110111",
	},
	{
		"OBJECT IDENTIFIER",
		[]byte{0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d},
		6,
		6,
		"1.2.840.113549",
	},
}

func TestParse(t *testing.T) {
	for _, test := range fieldParsingTests {
		t.Run(test.name, func(t *testing.T) {
			enc, _, err := Parse(test.octets, 0)
			assert.NilError(t, err)
			assert.Equal(t, enc.Tag, test.expectedTag, toUniversalTagName(test.expectedTag))
			assert.Equal(t, enc.Length, test.expectedLength)
			assert.Equal(t, enc.Content, test.expectedContent)
		})
	}
}
