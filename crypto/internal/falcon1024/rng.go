package falcon1024

import (
	"crypto/sha3"
	"encoding/binary"
	"io"
	"math/bits"
)

type samplerPRNG struct {
	r       io.Reader
	buf     [512]byte
	ptr     int
	state   [12]uint32
	counter uint64
}

func newSamplerPRNG(rng *sha3.SHAKE) *samplerPRNG {
	var seed [56]byte
	rng.Read(seed[:])

	p := &samplerPRNG{}
	for i := range p.state {
		p.state[i] = binary.LittleEndian.Uint32(seed[4*i:])
	}
	p.counter = binary.LittleEndian.Uint64(seed[48:])
	p.refill()

	return p
}

func newSamplerPRNGFromReader(r io.Reader) *samplerPRNG {
	return &samplerPRNG{r: r}
}

func (p *samplerPRNG) readByte() byte {
	if p.r != nil {
		var buf [1]byte
		p.read(buf[:])
		return buf[0]
	}

	v := p.buf[p.ptr]
	p.ptr++
	if p.ptr == len(p.buf) {
		p.refill()
	}
	return v
}

func (p *samplerPRNG) readUint64() uint64 {
	if p.r != nil {
		var buf [8]byte
		p.read(buf[:])
		return binary.LittleEndian.Uint64(buf[:])
	}

	if p.ptr >= len(p.buf)-9 {
		p.refill()
	}
	v := binary.LittleEndian.Uint64(p.buf[p.ptr:])
	p.ptr += 8
	return v
}

func (p *samplerPRNG) read(buf []byte) {
	if _, err := io.ReadFull(p.r, buf); err != nil {
		panic("falcon1024: short sampler PRNG reader")
	}
}

func (p *samplerPRNG) refill() {
	const (
		cw0 uint32 = 0x61707865
		cw1 uint32 = 0x3320646e
		cw2 uint32 = 0x79622d32
		cw3 uint32 = 0x6b206574
	)

	cc := p.counter
	for u := range 8 {
		state := [16]uint32{
			cw0, cw1, cw2, cw3,
			p.state[0], p.state[1], p.state[2], p.state[3],
			p.state[4], p.state[5], p.state[6], p.state[7],
			p.state[8], p.state[9],
			p.state[10] ^ uint32(cc),
			p.state[11] ^ uint32(cc>>32),
		}

		for range 10 {
			chachaQuarterRound(&state, 0, 4, 8, 12)
			chachaQuarterRound(&state, 1, 5, 9, 13)
			chachaQuarterRound(&state, 2, 6, 10, 14)
			chachaQuarterRound(&state, 3, 7, 11, 15)
			chachaQuarterRound(&state, 0, 5, 10, 15)
			chachaQuarterRound(&state, 1, 6, 11, 12)
			chachaQuarterRound(&state, 2, 7, 8, 13)
			chachaQuarterRound(&state, 3, 4, 9, 14)
		}

		state[0] += cw0
		state[1] += cw1
		state[2] += cw2
		state[3] += cw3
		for v := 4; v < 14; v++ {
			state[v] += p.state[v-4]
		}
		state[14] += p.state[10] ^ uint32(cc)
		state[15] += p.state[11] ^ uint32(cc>>32)
		cc++

		for v := range state {
			binary.LittleEndian.PutUint32(p.buf[(u<<2)+(v<<5):], state[v])
		}
	}

	p.counter = cc
	p.ptr = 0
}

func chachaQuarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] = bits.RotateLeft32(state[d]^state[a], 16)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], 12)
	state[a] += state[b]
	state[d] = bits.RotateLeft32(state[d]^state[a], 8)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], 7)
}
