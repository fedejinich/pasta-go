package pasta

import (
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type BFVUtil struct {
	bfvParams bfv.Parameters
	encoder   bfv.Encoder
	evaluator bfv.Evaluator
}

func NewBFVUtil(bfvParams bfv.Parameters, encoder bfv.Encoder, evaluator bfv.Evaluator) BFVUtil {
	return BFVUtil{bfvParams, encoder, evaluator}
}

func (bfvUtil *BFVUtil) matmulDecomp(state *rlwe.Ciphertext, mat1 [][]uint64, mat2 [][]uint64, sealParams SealParams) {
	// todo(fedejinich) should also implement 'baby step gigant step'
	matrixDim := PastaT

	if uint64(matrixDim*2) != sealParams.Slots && uint64(matrixDim*4) > sealParams.Slots {
		panic("too little slots for matmul implementation!")
	}

	// todo(fedejinich) not sure about this (
	// non-full-packed rotation preparation
	if sealParams.Halfslots != uint64(matrixDim) {
		stateRot := bfvUtil.evaluator.RotateColumnsNew(state, matrixDim) // todo(fedejinich) i'm 80% sure this is not right
		bfvUtil.evaluator.Add(state, stateRot, state)
	}

	// diagonal method preparation
	matrix := make([]rlwe.Plaintext, matrixDim)
	for i := 0; i < matrixDim; i++ {
		diag := make([]uint64, uint64(matrixDim)+sealParams.Halfslots)
		for j := 0; j < matrixDim; j++ {
			diag[j] = mat1[j][(j+matrixDim-i)%matrixDim]
			diag[uint64(j)+sealParams.Halfslots] = mat2[j][(j+matrixDim-i)%matrixDim]
		}
		row := bfv.NewPlaintext(bfvUtil.bfvParams, bfvUtil.bfvParams.MaxLevel()) // todo(fedejinich) not sure about MaxLevel
		bfvUtil.encoder.Encode(diag, row)
		matrix = append(matrix, *row) // todo(fedejinich) is matrix updated?
	}

	// todo(fedejinich) not sure about degree and level
	sum := state
	bfvUtil.evaluator.Mul(sum, &matrix[0], sum)
	for i := 1; i < matrixDim; i++ {
		bfvUtil.evaluator.RotateColumns(state, -1, state) // todo(fedejinich) this is called 'rotate_rows' in SEAL
		tmp := bfvUtil.evaluator.MulNew(state, &matrix[i])
		bfvUtil.evaluator.Add(sum, tmp, sum)
	}

	state = sum
}

func (bfvUtil *BFVUtil) addRcDecomp(state *rlwe.Ciphertext, rc []uint64) {
	roundConstants := bfv.NewPlaintext(bfvUtil.bfvParams, state.Level()) // todo(fedejinich) not sure about Level
	bfvUtil.encoder.Encode(rc, roundConstants)
	bfvUtil.evaluator.Add(state, roundConstants, state)
}

func (bfvUtil *BFVUtil) mixDecomp(state *rlwe.Ciphertext) {
	tmp := bfvUtil.evaluator.RotateRowsNew(state) // todo(fedejinich) this is called 'rotate_columns' in SEAL
	bfvUtil.evaluator.Add(tmp, state, state)
	bfvUtil.evaluator.Add(state, tmp, state)
}

func (bfvUtil BFVUtil) sboxCubeDecomp(state *rlwe.Ciphertext) {
	for i := 0; i < 3; i++ {
		bfvUtil.evaluator.Mul(state, state, state)
	}
}

func (bfvUtil *BFVUtil) sboxFeistelDecomp(state *rlwe.Ciphertext, sealParams SealParams) {
	// rotate state
	stateRot := bfvUtil.evaluator.RotateColumnsNew(state, -1) // todo(fedejinich) this is called 'rotate_rows' in SEAL

	// mask rotate state
	mask := bfv.NewPlaintext(bfvUtil.bfvParams, state.Level()) // todo(fedejinich) not sure about 'Level'
	maskVec := make([]uint64, PastaT+sealParams.Halfslots)
	for i := range maskVec {
		maskVec[i] = 1 // todo(fedejinich) is this ok?
	}
	maskVec[0] = 0
	maskVec[sealParams.Halfslots] = 0
	for i := uint64(PastaT); i < sealParams.Halfslots; i++ {
		maskVec[i] = 0
	}
	bfvUtil.encoder.Encode(maskVec, mask)
	bfvUtil.evaluator.Mul(stateRot, mask, stateRot)
	// stateRot = 0, x_1, x_2, x_3, .... x_(t-1)

	// square
	bfvUtil.evaluator.Mul(stateRot, stateRot, stateRot)
	bfvUtil.evaluator.Relinearize(stateRot, stateRot)
	// stateRot = 0, x_1^2, x_2^2, x_3^2, .... x_(t-1)^2

	bfvUtil.evaluator.Add(state, stateRot, state)
	// state = x_1, x_1^2 + x_2, x_2^2 + x_3, x_3^2 + x_4, .... x_(t-1)^2 + x_t
}
