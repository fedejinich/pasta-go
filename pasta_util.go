package pasta_go

import "C"
import (
	"encoding/binary"
)

const KeySizePasta3 = 256
const PlainSizePasta3 = 128
const CipherSizePasta3 = 128

const PastaT = PlainSizePasta3 // plain text size
const PastaR = 3               // number of rounds

type KeyBlock []uint64
type Block [PastaT]uint64

type PastaUtil struct {
	//shake128_ C.Keccak_HashInstance todo(fedejinich) this is not necesary
	key_    KeyBlock
	state1_ Block
	state2_ Block

	maxPrimeSize uint64
	pastaP       uint64
}

func NewPastaUtil(key []uint64, modulus uint64) *PastaUtil {
	var state1, state2 [128]uint64

	p := modulus
	maxPrimeSize := uint64(0)
	for p > 0 {
		maxPrimeSize++
		p >>= 1
	}
	maxPrimeSize = (1 << maxPrimeSize) - 1

	return &PastaUtil{
		key,
		state1,
		state2,
		maxPrimeSize,
		modulus,
	}
}

// todo(fedejinich) i gues i can remove both params, need to check that
func (p *PastaUtil) Keystream(nonce uint64, blockCounter uint64) Block {
	return p.genKeystream(nonce, blockCounter)
}

func (p *PastaUtil) GetRandomVector(allowZero bool) []uint64 {
	rc := make([]uint64, PastaT)
	for i := uint16(0); i < PastaT; i++ {
		rc[i] = p.generateRandomFieldElement(allowZero)
	}
	return rc
}

func (p *PastaUtil) generateRandomFieldElement(allowZero bool) uint64 {
	var randomBytes [8]byte
	for {
		// todo(fedejinich) should use the equivalent shake128 for go (i guess it's in the math lib)
		//if err := KeccakHashSqueeze(&shake128, randomBytes[:]); err != nil {
		//	panic("SHAKE128 squeeze failed")
		//}
		ele := binary.BigEndian.Uint64(randomBytes[:]) & p.maxPrimeSize
		if !allowZero && ele == 0 {
			continue
		}
		if ele < p.pastaP {
			return ele
		}
	}
}

func (p *PastaUtil) genKeystream(nonce, blockCounter uint64) Block {
	//p.initShake(nonce, blockCounter) // todo(fedejinich) i guess this can be removed

	// init state
	for i := 0; i < PastaT; i++ {
		p.state1_[i] = p.key_[i]
		p.state2_[i] = p.key_[PastaT+i]
	}

	for r := 0; r < PastaR; r++ {
		p.round(r)
	}

	// final affine with mixing afterwards
	p.linearLayer()

	return p.state1_
}

func (p *PastaUtil) round(r int) {
	p.linearLayer()

	if r == PastaR-1 {
		p.sboxCube(p.state1_)
		p.sboxCube(p.state2_)
	} else {
		p.sboxFeistel(p.state1_)
		p.sboxFeistel(p.state2_)
	}
}

func (p *PastaUtil) linearLayer() {
	p.matmul(p.state1_)
	p.matmul(p.state2_)
	p.addRc(p.state1_)
	p.addRc(p.state2_)
	p.mix()
}

func (p *PastaUtil) addRc(state Block) {
	for i := 0; i < PastaT; i++ {
		// ld(rasta_prime) ~ 60, no uint128_t for addition necessary
		state[i] = (state[i] + p.generateRandomFieldElement(true)) % p.pastaP
	}
}

func (p *PastaUtil) sboxCube(state Block) { // todo(fedejinich) i think type should change into *Block
	for i := 0; i < PastaT; i++ {
		square := (uint128(state[i]) * state[i]) % p.pastaP
		state[i] = uint64((uint128(square) * state[i]) % p.pastaP)
	}
}

func (p *PastaUtil) sboxFeistel(state Block) {
	var newState *Block
	newState[0] = state[0]
	for i := 1; i < PastaT; i++ {
		square := (uint128(state[i-1]) * state[i-1]) % p.pastaP
		// ld(rasta_prime) ~ 60, no uint128_t for addition necessary
		newState[i] = (uint64(square) + state[i]) % p.pastaP
	}
	state = *newState // todo(fedejinich) should i mutate the 'state' pointer? i guess so, check this
}

func (p *PastaUtil) matmul(state Block) { // todo(fedejinich) i think type should change into *Block
	newState := Block{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	rand := p.GetRandomVector(false)
	currRow := rand

	for i := 0; i < PastaT; i++ {
		for j := 0; j < PastaT; j++ {
			mult := (currRow[j] * state[j]) % p.pastaP
			newState[i] = (newState[i] + mult) % p.pastaP
		}
		if i != PastaT-1 {
			currRow = p.calculateRow(currRow, rand)
		}
	}
	state = newState
}

func (p *PastaUtil) calculateRow(prevRow, firstRow []uint64) []uint64 {
	out := make([]uint64, PastaT)
	for j := 0; j < PastaT; j++ {
		tmp := (uint128(firstRow[j]) * prevRow[PastaT-1]) % p.pastaP
		if j > 0 {
			// ld(rasta_prime) ~ 60, no uint128_t for addition necessary
			tmp = (tmp + prevRow[j-1]) % p.pastaP
		}
		out[j] = uint64(tmp)
	}
	return out
}

func (p *PastaUtil) mix() {
	for i := 0; i < PastaT; i++ {
		sum := (p.state1_[i] + p.state2_[i]) % p.pastaP
		p.state1_[i] = (p.state1_[i] + sum) % p.pastaP
		p.state2_[i] = (p.state2_[i] + sum) % p.pastaP
	}
}