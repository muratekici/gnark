package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"os"
	"reflect"
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
	// binary dump
	{
		fmt.Println("r1cs dump")
		r1csDump, _ := os.Create("r1cs.dump")
		writer := bufio.NewWriter(r1csDump)
		enc := gob.NewEncoder(writer)
		enc.Encode(ccs)
		r1csDump.Close()

		tCheck := time.Now()
		fmt.Println("r1cs single load", tCheck)
		r1csDump, _ = os.Open("r1cs.dump")
		ccs2 := groth16.NewCS(ecc.BN254)
		reader := bufio.NewReader(r1csDump)
		dec := gob.NewDecoder(reader)
		dec.Decode(ccs2)
		fmt.Println()
		fmt.Println("############################################################")
		fmt.Println("r1cs binary single load finished", time.Since(tCheck))
		fmt.Println("############################################################")
		fmt.Println()

		// fmt.Println("size of ccs3r:", size.Of(ccs3r))
		// fmt.Println("size of ccs3r.system:", size.Of(ccs3r.R1CSCore.System))
		// fmt.Println("size of ccs3r.constraints:", size.Of(ccs3r.R1CSCore.Constraints))

	}

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
		fmt.Println("r1cs cbor single load finished", time.Since(tCheck))
		ccs3 := ccs2.(*bn254r1cs.R1CS)

		// fmt.Println("size of ccs3:", size.Of(ccs3))
		// fmt.Println("size of ccs3.system:", size.Of(ccs3.R1CSCore.System))
		// fmt.Println("size of ccs3.constraints:", size.Of(ccs3.R1CSCore.Constraints))
		batchSize := 100000 // 1 << 18
		SplitDumpR1CS(ccs3, "LoadTestFoo", batchSize)

		tCheck = time.Now()
		fmt.Println("r1cs cbor multi load", tCheck)
		// ccs3r := LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), 10000)
		ccsf := LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), batchSize, runtime.NumCPU())
		fmt.Println()
		fmt.Println("############################################################")
		fmt.Println("r1cs cbor multi load finished", time.Since(tCheck))
		fmt.Println("############################################################")
		fmt.Println()

		if !reflect.DeepEqual(ccsf, ccs2) {
			panic("the recover constraints is not the same")
		}

		// fmt.Println("size of ccs3r:", size.Of(ccs3r))
		// fmt.Println("size of ccs3r.system:", size.Of(ccs3r.R1CSCore.System))
		// fmt.Println("size of ccs3r.constraints:", size.Of(ccs3r.R1CSCore.Constraints))

	}

	//ccs.Lazify()

	fmt.Println("after lazified cs size:", len(ccs.(*bn254r1cs.R1CS).Constraints))

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
		fmt.Println("r1cs binary single load finished", time.Since(tCheck))
		ccs3 := ccs2.(*bn254r1cs.R1CS)

		// fmt.Println("size of ccs3:", size.Of(ccs3))
		// fmt.Println("size of ccs3.system:", size.Of(ccs3.R1CSCore.System))
		// fmt.Println("size of ccs3.constraints:", size.Of(ccs3.R1CSCore.Constraints))
		batchSize := 100000 // 1 << 18
		SplitDumpR1CSBinary(ccs3, "LoadTestFoo", batchSize)

		tCheck = time.Now()
		fmt.Println("r1cs multi load", tCheck)
		// ccs3r := LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), 10000)
		ccsf := LoadSplittedR1CSConcurrentBinary("LoadTestFoo", len(ccs3.Constraints), batchSize, runtime.NumCPU())
		fmt.Println()
		fmt.Println("############################################################")
		fmt.Println("r1cs binary multi load finished", time.Since(tCheck))
		fmt.Println("############################################################")
		fmt.Println()

		if !reflect.DeepEqual(ccsf, ccs2) {
			panic("the recover constraints is not the same")
		}
		// fmt.Println("size of ccs3r:", size.Of(ccs3r))
		// fmt.Println("size of ccs3r.system:", size.Of(ccs3r.R1CSCore.System))
		// fmt.Println("size of ccs3r.constraints:", size.Of(ccs3r.R1CSCore.Constraints))
		//pk, vk, _ := groth16.Setup(ccsf)
		//
		//assignment := Circuit{
		//	PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		//	Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
		//}
		//witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		//publicWitness, _ := witness.Public()
		//
		//// groth16: Prove & Verify
		//proof, _ := groth16.Prove(ccs, pk, witness)
		//err := groth16.Verify(proof, vk, publicWitness)
		//if err != nil {
		//	panic(err)
		//}
	}
}
