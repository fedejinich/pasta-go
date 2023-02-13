package pasta_go

import (
	"math"
)

type CipherParams struct {
	KeySize    uint64
	PlainSize  uint64
	CipherSize uint64
}

type Pasta struct {
	SecretKey []uint64
	Modulus   uint64
	Params    CipherParams
}

func NewPasta3(secretKey []uint64, modulus uint64) *Pasta {
	pasta3 := Pasta{
		secretKey,
		modulus,
		CipherParams{
			KeySizePasta3,
			PlainSizePasta3,
			CipherSizePasta3,
		},
	}

	return &pasta3
}

func (p *Pasta) Encrypt(plaintext []uint64) []uint64 {
	nonce := uint64(123456789)
	size := len(plaintext)

	numBlock := int(math.Ceil(float64(size) / float64(p.Params.PlainSize)))

	pastaUtil := NewPastaUtil(p.SecretKey, p.Modulus)
	ciphertext := make([]uint64, size)
	copy(ciphertext, plaintext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pastaUtil.Keystream(nonce, b)
		for i := int(b * p.Params.PlainSize); i < int((b+1)*p.Params.PlainSize) && i < size; i++ {
			ciphertext[i] = (ciphertext[i] + ks[i-int(b*p.Params.PlainSize)]) % p.Modulus
		}
	}

	return ciphertext
}

func (p *Pasta) Decrypt(ciphertext []uint64) []uint64 {
	nonce := uint64(123456789)
	size := len(ciphertext)

	numBlock := int(math.Ceil(float64(size) / float64(p.Params.CipherSize)))

	pasta := NewPastaUtil(p.SecretKey, p.Modulus)
	plaintext := make([]uint64, size)
	copy(plaintext, ciphertext)

	for b := uint64(0); b < uint64(numBlock); b++ {
		ks := pasta.Keystream(nonce, b)
		for i := int(b * p.Params.CipherSize); i < int((b+1)*p.Params.CipherSize) && i < size; i++ {
			if ks[i-int(b*p.Params.PlainSize)] > plaintext[i] {
				plaintext[i] += p.Modulus
			}
			plaintext[i] = plaintext[i] - ks[i-int(b*p.Params.PlainSize)]
		}
	}

	return plaintext
}
