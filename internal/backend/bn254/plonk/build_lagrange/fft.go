package build_lagrange

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"math/bits"
)

func Butterfly(a *bn254.G1Jac, b *bn254.G1Jac) {
	t := *a
	a.AddAssign(b)
	t.SubAssign(b)
	*b = t
}

// kerDIT8 is a kernel that process a FFT of size 8
func kerDIT8(a []bn254.G1Jac, twiddles [][]fr.Element, stage int) {
	Butterfly(&a[0], &a[1])
	Butterfly(&a[2], &a[3])
	Butterfly(&a[4], &a[5])
	Butterfly(&a[6], &a[7])
	Butterfly(&a[0], &a[2])

	var twiddle big.Int
	twiddles[stage+1][1].ToBigInt(&twiddle)
	a[3].ScalarMultiplication(&a[3], &twiddle)

	Butterfly(&a[1], &a[3])
	Butterfly(&a[4], &a[6])
	a[7].ScalarMultiplication(&a[7], &twiddle)

	Butterfly(&a[5], &a[7])
	Butterfly(&a[0], &a[4])

	twiddles[stage+0][1].ToBigInt(&twiddle)
	a[5].ScalarMultiplication(&a[5], &twiddle)

	Butterfly(&a[1], &a[5])
	twiddles[stage+0][2].ToBigInt(&twiddle)
	a[6].ScalarMultiplication(&a[6], &twiddle)

	Butterfly(&a[2], &a[6])
	twiddles[stage+0][3].ToBigInt(&twiddle)
	a[7].ScalarMultiplication(&a[7], &twiddle)

	Butterfly(&a[3], &a[7])
}

// KerDIF8 is a kernel that process a FFT of size 8
func KerDIF8(a []bn254.G1Jac, twiddles [][]fr.Element, stage int) {
	Butterfly(&a[0], &a[4])
	Butterfly(&a[1], &a[5])
	Butterfly(&a[2], &a[6])
	Butterfly(&a[3], &a[7])

	var twiddle big.Int
	twiddles[stage+0][1].ToBigInt(&twiddle)
	a[5].ScalarMultiplication(&a[5], &twiddle)
	twiddles[stage+0][2].ToBigInt(&twiddle)
	a[6].ScalarMultiplication(&a[6], &twiddle)
	twiddles[stage+0][3].ToBigInt(&twiddle)
	a[7].ScalarMultiplication(&a[7], &twiddle)
	Butterfly(&a[0], &a[2])
	Butterfly(&a[1], &a[3])
	Butterfly(&a[4], &a[6])
	Butterfly(&a[5], &a[7])
	twiddles[stage+1][1].ToBigInt(&twiddle)
	a[3].ScalarMultiplication(&a[3], &twiddle)
	twiddles[stage+1][1].ToBigInt(&twiddle)
	a[7].ScalarMultiplication(&a[7], &twiddle)
	Butterfly(&a[0], &a[1])
	Butterfly(&a[2], &a[3])
	Butterfly(&a[4], &a[5])
	Butterfly(&a[6], &a[7])
}

// parallelize threshold for a single butterfly op, if the fft stage is not parallelized already
const butterflyThreshold = 16

func DifFFT(a []bn254.G1Jac, twiddles [][]fr.Element, stage, maxSplits int, chDone chan struct{}) {
	if chDone != nil {
		defer close(chDone)
	}

	n := len(a)
	if n == 1 {
		return
	} else if n == 8 {
		KerDIF8(a, twiddles, stage)
		return
	}
	m := n >> 1

	Butterfly(&a[0], &a[m])

	var twiddle big.Int
	for i := 1; i < m; i++ {
		Butterfly(&a[i], &a[i+m])
		twiddles[stage][i].ToBigInt(&twiddle)
		a[i+m].ScalarMultiplication(&a[i+m], &twiddle)
	}

	if m == 1 {
		return
	}

	nextStage := stage + 1
	if stage < maxSplits {
		chDone := make(chan struct{}, 1)
		go DifFFT(a[m:n], twiddles, nextStage, maxSplits, chDone)
		DifFFT(a[0:m], twiddles, nextStage, maxSplits, nil)
		<-chDone
	} else {
		DifFFT(a[0:m], twiddles, nextStage, maxSplits, nil)
		DifFFT(a[m:n], twiddles, nextStage, maxSplits, nil)
	}
}

func DitFFT(a []bn254.G1Jac, twiddles [][]fr.Element, stage, maxSplits int, chDone chan struct{}) {
	if chDone != nil {
		defer close(chDone)
	}
	n := len(a)
	if n == 1 {
		return
	} else if n == 8 {
		kerDIT8(a, twiddles, stage)
		return
	}
	m := n >> 1

	nextStage := stage + 1

	if stage < maxSplits {
		// that's the only time we fire go routines
		chDone := make(chan struct{}, 1)
		go DitFFT(a[m:], twiddles, nextStage, maxSplits, chDone)
		DitFFT(a[0:m], twiddles, nextStage, maxSplits, nil)
		<-chDone
	} else {
		DitFFT(a[0:m], twiddles, nextStage, maxSplits, nil)
		DitFFT(a[m:n], twiddles, nextStage, maxSplits, nil)
	}

	Butterfly(&a[0], &a[m])
	var twiddle big.Int
	for k := 1; k < m; k++ {
		twiddles[stage][k].ToBigInt(&twiddle)
		a[k+m].ScalarMultiplication(&a[k+m], &twiddle)
		Butterfly(&a[k], &a[k+m])
	}
}

func ToJac(a []bn254.G1Affine) []bn254.G1Jac {
	res := make([]bn254.G1Jac, len(a))
	for i := 0; i < len(a); i++ {
		res[i].FromAffine(&a[i])
	}
	return res
}

func FromJac(a []bn254.G1Jac) []bn254.G1Affine {
	res := make([]bn254.G1Affine, len(a))
	for i := 0; i < len(a); i++ {
		res[i].FromJacobian(&a[i])
	}
	return res
}

func BitReversePoints(a []bn254.G1Jac) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}
