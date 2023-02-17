package build_lagrange

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"math/big"
	"math/bits"
	"runtime"
)

type G1SRS []bn254.G1Affine
type G2SRS [2]bn254.G2Affine

func BuildLagrange(curSrs G1SRS, size int) (G1SRS, error) {
	domain := fft.NewDomain(uint64(size))
	newSrs := make([]bn254.G1Affine, size)

	numCPU := uint64(runtime.NumCPU())
	maxSplits := bits.TrailingZeros64(ecc.NextPowerOfTwo(numCPU))

	copy(newSrs[:], curSrs[:size])

	newSrsJac := ToJac(newSrs)
	DifFFT(newSrsJac, domain.TwiddlesInv, 0, maxSplits, nil)
	BitReversePoints(newSrsJac)
	resNewSrs := FromJac(newSrsJac)

	var invBigint big.Int
	domain.CardinalityInv.ToBigInt(&invBigint)

	for i := 0; i < size; i++ {
		resNewSrs[i].ScalarMultiplication(&resNewSrs[i], &invBigint)
	}

	return resNewSrs, nil
}
