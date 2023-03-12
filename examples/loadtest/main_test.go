package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestC(t *testing.T) {

	var circuit Circuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}
	fmt.Println("cs size:", ccs.GetNbConstraints())

	// Correct data: the proof passes
	{
		fmt.Println("r1cs dump")
		r1csDump, _ := os.Create("r1cs.dump")
		_, _ = ccs.WriteTo(r1csDump)
		r1csDump.Close()

		tCheck := time.Now()
		fmt.Println("r1cs single load", tCheck)
		r1csDump, _ = os.Open("r1cs.dump")
		ccs2 := groth16.NewCS(ecc.BN254)
		_, _ = ccs2.ReadFrom(r1csDump)
		fmt.Println("r1cs single load finished", time.Since(tCheck))
		ccs3 := ccs2.(*bn254r1cs.R1CS)

		// fmt.Println("size of ccs3:", size.Of(ccs3))
		// fmt.Println("size of ccs3.system:", size.Of(ccs3.R1CSCore.System))
		// fmt.Println("size of ccs3.constraints:", size.Of(ccs3.R1CSCore.Constraints))
		batchSize := 100000 // 1 << 18
		SplitDumpR1CS(ccs3, "LoadTestFoo", batchSize)

		tCheck = time.Now()
		fmt.Println("r1cs multi load", tCheck)
		// ccs3r := LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), 10000)
		LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), batchSize, runtime.NumCPU())
		fmt.Println("r1cs multi load finished", time.Since(tCheck))
		// fmt.Println("size of ccs3r:", size.Of(ccs3r))
		// fmt.Println("size of ccs3r.system:", size.Of(ccs3r.R1CSCore.System))
		// fmt.Println("size of ccs3r.constraints:", size.Of(ccs3r.R1CSCore.Constraints))

	}

}
