// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	groth16_bn254 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"log"
	"os"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/DmitriyVTitov/size"
)

// In this example we show how to use PLONK with KZG commitments. The circuit that is

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	for i := 0; i < 1000; i++ {
		mimc, _ := mimc.NewMiMC(api)
		mimc.Write(circuit.PreImage)
		api.AssertIsEqual(circuit.Hash, mimc.Sum())
	}

	return nil
}

func SplitDumpPK(pk *groth16_bn254.ProvingKey, session string) error {
	// E part
	{
		pk2 := &groth16_bn254.ProvingKey{}
		pk2.G1.Alpha = pk.G1.Alpha
		pk2.G1.Beta = pk.G1.Beta
		pk2.G1.Delta = pk.G1.Delta
		pk2.G2.Beta = pk.G2.Beta
		pk2.G2.Delta = pk.G2.Delta
		pk2.CommitmentKey = pk.CommitmentKey

		name := fmt.Sprintf("%s.pk.E.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := pk2.WriteRawTo(pkFile)
		fmt.Println("written ", cnt, "bytes for pk.E.save")
	}

	// A part
	{
		pk2 := &groth16_bn254.ProvingKey{}
		pk2.G1.A = pk.G1.A

		name := fmt.Sprintf("%s.pk.A.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := pk2.WriteRawTo(pkFile)
		fmt.Println("written ", cnt, "bytes for pk.A.save")

	}

	// B1 part
	{
		pk2 := &groth16_bn254.ProvingKey{}
		pk2.G1.B = pk.G1.B

		name := fmt.Sprintf("%s.pk.B1.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := pk2.WriteRawTo(pkFile)
		fmt.Println("written ", cnt, "bytes for pk.B1.save")

	}

	// K part
	{
		pk2 := &groth16_bn254.ProvingKey{}
		pk2.G1.K = pk.G1.K

		name := fmt.Sprintf("%s.pk.K.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := pk2.WriteRawTo(pkFile)
		fmt.Println("written ", cnt, "bytes for pk.K.save")

	}

	// Z part
	{
		pk2 := &groth16_bn254.ProvingKey{}
		pk2.G1.Z = pk.G1.Z

		name := fmt.Sprintf("%s.pk.Z.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := pk2.WriteRawTo(pkFile)
		fmt.Println("written ", cnt, "bytes for pk.Z.save")

	}

	// B2 part
	{
		pk2 := &groth16_bn254.ProvingKey{}
		pk2.G2.B = pk.G2.B

		name := fmt.Sprintf("%s.pk.B2.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := pk2.WriteRawTo(pkFile)
		fmt.Println("written ", cnt, "bytes for pk.B2.save")

	}

	return nil
}

func SplitDumpR1CS(ccs *bn254r1cs.R1CS, session string, batchSize int) error {
	// E part
	{
		ccs2 := &bn254r1cs.R1CS{}
		ccs2.CoeffTable = ccs.CoeffTable
		ccs2.R1CSCore.System = ccs.R1CSCore.System

		name := fmt.Sprintf("%s.r1cs.E.save", session)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := ccs2.WriteTo(csFile)
		fmt.Println("written ", cnt, name)
	}

	N := len(ccs.R1CSCore.Constraints)
	for i := 0; i < N; {
		// dump R1C[i, min(i+batchSize, end)]
		ccs2 := &bn254r1cs.R1CS{}
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		ccs2.R1CSCore.Constraints = ccs.R1CSCore.Constraints[i:iNew]
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		cnt, err := ccs2.WriteTo(csFile)
		fmt.Println("written ", cnt, name)

		i = iNew
	}

	return nil
}

func LoadSplittedR1CS(session string, N, batchSize int) *bn254r1cs.R1CS {
	ccs := &bn254r1cs.R1CS{}
	// E part
	{
		ccs2 := &bn254r1cs.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E.save", session)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		cnt, err := ccs2.ReadFrom(csFile)
		fmt.Println("read ", cnt, name)

		ccs.CoeffTable = ccs2.CoeffTable
		ccs.R1CSCore.System = ccs2.R1CSCore.System
	}
	ccs.R1CSCore.Constraints = make([]constraint.R1C, N)
	for i := 0; i < N; {
		// read R1C[i, min(i+batchSize, end)]
		ccs2 := &bn254r1cs.R1CS{}
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		cnt, err := ccs2.ReadFrom(csFile)
		fmt.Println("read ", cnt, name)
		copy(ccs.R1CSCore.Constraints[i:iNew], ccs2.R1CSCore.Constraints)

		i = iNew
	}

	return ccs
}

func LoadSplittedR1CSConcurrent(session string, N, batchSize int) *bn254r1cs.R1CS {
	ccs := &bn254r1cs.R1CS{}
	// E part
	{
		ccs2 := &bn254r1cs.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E.save", session)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		cnt, err := ccs2.ReadFrom(csFile)
		fmt.Println("read ", cnt, name)

		ccs.CoeffTable = ccs2.CoeffTable
		ccs.R1CSCore.System = ccs2.R1CSCore.System
	}
	ccs.R1CSCore.Constraints = make([]constraint.R1C, N)

	var wg sync.WaitGroup
	chTasks := make(chan int, runtime.NumCPU())
	// worker pool
	for core := 0; core < runtime.NumCPU(); core++ {
		go func() {
			for i := range chTasks {
				ccs2 := &bn254r1cs.R1CS{}
				iNew := i + batchSize
				if iNew > N {
					iNew = N
				}
				name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
				csFile, err := os.Open(name)
				if err != nil {
					panic(err)
				}
				cnt, err := ccs2.ReadFrom(csFile)
				fmt.Println("read ", cnt, name)
				copy(ccs.R1CSCore.Constraints[i:iNew], ccs2.R1CSCore.Constraints)

				wg.Done()
			}
		}()
	}

	defer func() {
		close(chTasks)
	}()

	for i := 0; i < N; {
		// read R1C[i, min(i+batchSize, end)]
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		wg.Add(1)
		chTasks <- i

		i = iNew
	}
	wg.Wait()

	return ccs
}

func main() {

	var circuit Circuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}
	fmt.Println("cs size:", ccs.GetNbConstraints())

	// Correct data: the proof passes
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w Circuit
		w.PreImage = "16130099170765464552823636852555369511329944820189892919423002775646948828469"
		w.Hash = "12886436712380113721405259596386800092738845035233065858332878701083870690753"

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		fmt.Println("setup...")
		pk, vk, err := groth16.Setup(ccs)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("size of pk:", size.Of(pk))
		pk2 := pk.(*groth16_bn254.ProvingKey)
		fmt.Println("size of pk:", size.Of(pk2))

		fmt.Println("r1cs dump")
		r1csDump, _ := os.Create("r1cs.dump")
		_, _ = ccs.WriteTo(r1csDump)
		r1csDump.Close()

		fmt.Println("r1cs load")
		r1csDump, _ = os.Open("r1cs.dump")
		ccs2 := groth16.NewCS(ecc.BN254)
		_, _ = ccs2.ReadFrom(r1csDump)
		fmt.Println("r1cs load finished")
		ccs3 := ccs2.(*bn254r1cs.R1CS)

		fmt.Println("size of ccs3:", size.Of(ccs3))
		fmt.Println("size of ccs3.system:", size.Of(ccs3.R1CSCore.System))
		fmt.Println("size of ccs3.constraints:", size.Of(ccs3.R1CSCore.Constraints))
		SplitDumpR1CS(ccs3, "LoadTestFoo", 10000)
		ccs33 := LoadSplittedR1CSConcurrent("LoadTestFoo", len(ccs3.Constraints), 10000)
		fmt.Println("size of ccs33:", size.Of(ccs33))
		fmt.Println("size of ccs33.system:", size.Of(ccs33.R1CSCore.System))
		fmt.Println("size of ccs33.constraints:", size.Of(ccs33.R1CSCore.Constraints))

		proof, err := groth16.Prove(ccs33, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		err = groth16.Verify(proof, vk, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}
	}

}
