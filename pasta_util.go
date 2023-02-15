package pasta_go

import "C"
import (
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"math/big"
)

const KeySizePasta3 = 256
const PlainSizePasta3 = 128
const CipherSizePasta3 = 128

const PastaT = PlainSizePasta3 // plain text size
const PastaR = 3               // number of rounds

type KeyBlock []uint64
type Block [PastaT]uint64

type PastaUtil struct {
	shake128_ sha3.ShakeHash

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
		nil, // todo(fedejinich) improve this
		key,
		state1,
		state2,
		maxPrimeSize,
		modulus,
	}
}

func (p *PastaUtil) Keystream(nonce uint64, blockCounter uint64) Block {
	p.InitShake(nonce, blockCounter)

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

func (p *PastaUtil) InitShake(nonce, blockCounter uint64) {
	seed := make([]byte, 16)

	binary.BigEndian.PutUint64(seed[:8], nonce)
	binary.BigEndian.PutUint64(seed[8:], blockCounter)

	shake := sha3.NewShake128()
	if _, err := shake.Write(seed); err != nil {
		panic("SHAKE128 update failed")
	}

	p.shake128_ = shake
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
		if _, err := p.shake128_.Read(randomBytes[:]); err != nil {
			panic("SHAKE128 squeeze failed")
		}

		ele := binary.BigEndian.Uint64(randomBytes[:]) & p.maxPrimeSize

		if !allowZero && ele == 0 {
			continue
		}

		if ele < p.pastaP {
			return ele
		}
	}
}

// The r-round Pasta construction to generate the keystream KN,i for block i under nonce N with affine layers Aj.
func (p *PastaUtil) round(r int) {
	// Ai
	p.linearLayer()

	// S(x) or S'(x)
	if r == PastaR-1 {
		p.sboxCube(&p.state1_)
		p.sboxCube(&p.state2_)
	} else {
		p.sboxFeistel(&p.state1_)
		p.sboxFeistel(&p.state2_)
	}
}

// Aij(y) = Mij X y + cij
func (p *PastaUtil) linearLayer() {
	p.matmul(&p.state1_)
	p.matmul(&p.state2_)

	p.addRc(&p.state1_)
	p.addRc(&p.state2_)

	p.mix()
}

// Mij X y
func (p *PastaUtil) matmul(state *Block) {
	newState := Block{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	rand := p.GetRandomVector(false)
	currRow := rand

	for i := 0; i < PastaT; i++ {
		for j := 0; j < PastaT; j++ {
			mult := new(big.Int).Mul(
				big.NewInt(int64(currRow[j])),
				big.NewInt(int64(state[j])),
			)
			modulus := big.NewInt(int64(p.pastaP))
			mult.Mod(mult, modulus)
			newState[i] = (newState[i] + mult.Uint64()) % p.pastaP
		}
		if i != PastaT-1 {
			currRow = p.calculateRow(currRow, rand)
		}
	}
	*state = newState
}

// + cij
func (p *PastaUtil) addRc(state *Block) {
	for i := 0; i < PastaT; i++ {
		randomFE := p.generateRandomFieldElement(true)

		currentState := big.NewInt(int64(state[i]))
		randomFEInt := big.NewInt(int64(randomFE))

		modulus := big.NewInt(int64(p.pastaP))
		currentState.Add(currentState, randomFEInt)
		currentState.Mod(currentState, modulus)

		state[i] = currentState.Uint64()
	}
}

// [S(x)]i = (x)3
func (p *PastaUtil) sboxCube(state *Block) {
	for i := 0; i < PastaT; i++ {
		currentState := big.NewInt(int64(state[i]))
		modulus := big.NewInt(int64(p.pastaP))

		square := new(big.Int).Mul(currentState, currentState)
		square.Mod(square, modulus)
		cube := square.Mul(square, currentState)

		state[i] = cube.Mod(cube, modulus).Uint64()
	}
}

// S'(x) = x + (rot(-1)(x) . m)^2
func (p *PastaUtil) sboxFeistel(state *Block) {
	pastaP := big.NewInt(int64(p.pastaP))
	var newState Block
	newState[0] = state[0]

	for i := 1; i < PastaT; i++ {
		stateBig := big.NewInt(int64(state[i-1]))

		square := new(big.Int).Mul(stateBig, stateBig)
		cube := square.Mod(square, pastaP)
		cubeAdd := cube.Add(cube, big.NewInt(int64(state[i])))
		newElem := cubeAdd.Mod(cubeAdd, pastaP)
		
		newState[i] = newElem.Uint64()
	}

	*state = newState
}

func (p *PastaUtil) calculateRow(prevRow, firstRow []uint64) []uint64 {
	out := make([]uint64, PastaT)

	prevRowLast := big.NewInt(int64(prevRow[PastaT-1]))

	for j := 0; j < PastaT; j++ {
		firstRowVal := big.NewInt(int64(firstRow[j]))

		tmp := new(big.Int).Mul(firstRowVal, prevRowLast)
		modulus := big.NewInt(int64(p.pastaP))
		tmp.Mod(tmp, modulus)

		if j > 0 {
			prevRowVal := big.NewInt(int64(prevRow[j-1]))
			tmp.Add(tmp, prevRowVal)
			tmp.Mod(tmp, modulus)
		}

		out[j] = tmp.Uint64()
	}

	return out
}

func (p *PastaUtil) mix() {
	for i := 0; i < PastaT; i++ {
		pastaP := big.NewInt(int64(p.pastaP))
		state1 := big.NewInt(int64(p.state1_[i]))
		state2 := big.NewInt(int64(p.state2_[i]))

		sum := new(big.Int).Add(state1, state2)
		sum = sum.Mod(sum, pastaP)

		sum1 := new(big.Int).Add(state1, sum)
		sum1 = sum1.Mod(sum1, pastaP)

		sum2 := new(big.Int).Add(state2, sum)
		sum2 = sum2.Mod(sum2, pastaP)

		p.state1_[i] = sum1.Uint64()
		p.state2_[i] = sum2.Uint64()
	}
}
