//+build gofuzz

package dagjson

import (
	"bytes"
	"fmt"
	basicnode "github.com/ipld/go-ipld-prime/node/basic"
	fleece "github.com/leastauthority/fleece/fuzzing"
	"reflect"
)

func FuzzMulticodecDecodeEncode(data []byte) int {
	builder1 := basicnode.Prototype.Any.NewBuilder()
	buf1 := bytes.NewBuffer(data)
	if err := Decoder(builder1, buf1); err != nil {
		return fleece.FuzzNormal
	}

	node1 := builder1.Build()
	buf2 := new(bytes.Buffer)
	if err := Encoder(node1, buf2); err != nil {
		panic(fmt.Errorf("unable to encode: %w", err))
	}

	builder2 := basicnode.Prototype.Any.NewBuilder()
	if err := Decoder(builder2, buf2); err != nil {
		panic(fmt.Errorf("unable to decode: %w", err))
	}

	node2 := builder2.Build()
	buf3 := new(bytes.Buffer)
	if err := Encoder(node2, buf3); err != nil {
		panic(fmt.Errorf("unable to re-encode: %w", err))
	}

	if !bytes.Equal(buf2.Bytes(), buf3.Bytes()) {
		panic("serialized messages are not deeply equal!")
	}

	if !reflect.DeepEqual(node1, node2) {
		panic("deserialized messages are not deeply equal!")
	}
	return fleece.FuzzInteresting
}
