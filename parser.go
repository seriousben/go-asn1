package parser

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

func ParsePemFile(filepath string) (*Encoding, error) {
	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ParsePem(b)
}

func ParsePem(b []byte) (*Encoding, error) {
	block, _ := pem.Decode(b)
	enc, _, err := Parse(block.Bytes, 0)
	return enc, err
}

func printByte(label string, b byte) {
	fmt.Printf("%s: %08b\n", label, b)
}

func toClassName(class int) string {
	var classNames = []string{
		"universal",        // 0
		"application",      // 1
		"context-specific", // 2
		"private",          // 3
	}
	if class < 0 || class >= len(classNames) {
		panic(fmt.Sprintf("unknown class %s", class))
	}
	return classNames[class]
}

func toPCName(pc int) string {
	var pcNamaes = []string{
		"Primitive (P)",   // 0
		"Constructed (C)", // 1
	}
	if pc < 0 || pc >= len(pcNamaes) {
		panic(fmt.Sprintf("unknown pc %s", pc))
	}
	return pcNamaes[pc]
}

func toUniversalTagName(tag int) string {
	var tagNames = []string{
		"End-of-Content (EOC)",     // 0
		"BOOLEAN",                  // 1
		"INTEGER",                  // 2
		"BIT STRING",               // 3
		"OCTET STRING",             // 4
		"NULL",                     // 5
		"OBJECT IDENTIFIER",        // 6
		"Object Descriptor",        // 7
		"EXTERNAL",                 // 8
		"REAL (float)",             // 9
		"ENUMERATED",               // 10
		"EMBEDDED PDV",             // 11
		"UTF8String",               // 12
		"RELATIVE-OID",             // 13
		"Reserved (14)",            // 14
		"Reserved (15)",            // 15
		"SEQUENCE and SEQUENCE OF", // 16
		"SET and SET OF",           // 17
		"NumericString",            // 18
		"PrintableString",          // 19
		"T61String",                // 20
		"VideotexString",           // 21
		"IA5String",                // 22
		"UTCTime",                  // 23
		"GeneralizedTime",          // 24
		"GraphicString",            // 25
		"VisibleString",            // 26
		"GeneralString",            // 27
		"UniversalString",          // 28
		"CHARACTER STRING",         // 29
		"BMPString",                // 30"
	}
	if tag < 0 || tag >= len(tagNames) {
		return fmt.Sprintf("<unknown universal tag %d>", tag)
	}
	return tagNames[tag]
}

// Encoding is an ASN.1 encoding
type Encoding struct {
	Offset            int
	Bytes             []byte
	Class             int
	ClassName         string
	PC                int
	PCName            string
	Tag               int
	TagName           string
	Length            int
	IsShortFormLength bool
	ContentBytes      []byte
	Content           interface{}
}

func (e *Encoding) toString(depth int) string {
	indent := ""
	for i := 0; i != depth; i++ {
		indent = fmt.Sprintf("%s ", indent)
	}
	header := fmt.Sprintf(
		"offset=%d class:%d(%s) pc:%d(%s) tag:%d(%s) length:%d(short:%t)",
		e.Offset, e.Class, e.ClassName, e.PC, e.PCName, e.Tag, e.TagName, e.Length, e.IsShortFormLength,
	)

	contentStr := ""
	switch content := e.Content.(type) {
	case []*Encoding:
		for _, enc := range content {
			contentStr = fmt.Sprintf("%s\n%s", contentStr, enc.toString(depth+1))
		}
	case string:
		contentStr = content
	default:
		panic(fmt.Sprintf("unknow %T", content))
	}
	return fmt.Sprintf("%s%s %s", indent, header, contentStr)
}

func (e *Encoding) String() string {
	return e.toString(0)
}

func parseContent(tag int, octets []byte, offset int, length int) (interface{}, error) {
	var value interface{}
	switch tag {
	case 16:
		// sequence
		var err error
		parseOffset := offset
		children := []*Encoding{}
		for {
			var child *Encoding
			child, parseOffset, err = Parse(octets, parseOffset)
			if err != nil {
				return nil, err
			}
			children = append(children, child)
			if parseOffset >= length {
				break
			}
		}
		value = children
	case 6:
		// object identifier
		oid := []string{}
		for _, n := range octets[offset : offset+length] {
			num, _ := strconv.ParseInt(fmt.Sprintf("%d", int(n)), 128, 8)
			oid = append(oid, fmt.Sprintf("%d", num))
		}
		value = strings.Join(oid, ".")
	case 3:
		// bitstring
		paddingLength := int(octets[offset])
		bitstring := ""
		for _, n := range octets[offset+1 : offset+length] {
			bitstring = fmt.Sprintf("%s%08b", bitstring, n)
		}
		bitstring = fmt.Sprintf("%s", bitstring)
		value = bitstring[0 : len(bitstring)-paddingLength]
	default:
		value = "<unsupported representation>"
	}
	return value, nil
}

func Parse(octets []byte, startOffset int) (*Encoding, int, error) {
	tagMask := byte(0x1F) // 00011111
	offset := startOffset

	idOctet := octets[offset]
	class := int(idOctet >> 6)
	pc := int(idOctet >> 5 & 1) // TODO: test 10100000
	tag := int(idOctet & tagMask)
	tagName := toUniversalTagName(tag)

	offset++
	firstLengthOctet := octets[offset]
	isLengthShortForm := firstLengthOctet&0x80 == 0 // 10000000

	contentLength := int(firstLengthOctet & 0x7F) // 01111111
	if !isLengthShortForm && contentLength == 0 {
		return nil, offset, fmt.Errorf("indefinite length is not supported [identity:%08b length:%08b class:%d(%s) tag:%d]", idOctet, firstLengthOctet, class, toClassName(class), tag, tagName)
	} else if !isLengthShortForm {
		//lengthOctets := octets[offset:contentLength]
		//fmt.Println(int(lengthOctets))

		return nil, offset, fmt.Errorf("definite long length is not supported [identity:%08b length:%08b class:%d(%s) tag:%d]", idOctet, firstLengthOctet, class, toClassName(class), tag, tagName)
	}

	offset++

	encoding := Encoding{
		Offset:            startOffset,
		Bytes:             octets[startOffset : offset+contentLength],
		Class:             class,
		ClassName:         toClassName(class),
		PC:                pc,
		PCName:            toPCName(pc),
		Tag:               tag,
		TagName:           tagName,
		Length:            contentLength,
		IsShortFormLength: isLengthShortForm,
		ContentBytes:      octets[offset : offset+contentLength],
		Content:           nil,
	}

	content, err := parseContent(tag, octets, offset, contentLength)
	encoding.Content = content

	offset = offset + contentLength
	return &encoding, offset, err
}
