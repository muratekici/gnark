package rollup

import (
	"encoding/json"
	"fmt"
	"github.com/DmitriyVTitov/size"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	backend_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	groth16_bn254 "github.com/consensys/gnark/internal/backend/bn254/groth16"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	"github.com/consensys/gnark/test"
	"runtime"

	"os"
	"testing"
	"time"
)

func TestSolve(t *testing.T) {
	mainStart := time.Now()
	assert := test.NewAssert(t)

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Init operator
	var rollupCircuit Circuit
	var witnessFull, witnessPub *witness.Witness
	{
		operator, users := createOperator(nbAccounts)
		sender, err := operator.readAccount(0)
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := operator.readAccount(1)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < batchSize; i++ {
			// create the transfer and sign it
			amount := uint64(0)
			transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce+uint64(i))

			// sign the transfer
			_, err = transfer.Sign(users[0], operator.h)
			if err != nil {
				t.Fatal(err)
			}
			err = operator.updateState(transfer, i)
			if err != nil {
				t.Fatal(err)
			}
		}
		witnessFull, err = frontend.NewWitness(&operator.witnesses, ecc.BN254)
		assert.NoError(err, "witnessFull")
		witnessPub, err = frontend.NewWitness(&operator.witnesses, ecc.BN254, frontend.PublicOnly())
		assert.NoError(err, "witnessPub")
		fmt.Println("size of witnessFull:", size.Of(witnessFull))
		fmt.Println("size of witnessPub:", size.Of(witnessPub))
		fmt.Println("##### operator ready", time.Since(mainStart))

	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Compile circuit
	cccs := &backend_bn254.R1CS{}
	{
		fmt.Println("##### Compiling@", time.Since(mainStart))
		ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &rollupCircuit, frontend.IgnoreUnconstrainedInputs())
		assert.NoError(err, "compile")
		nbInternal, nbSecret, nbPublic := ccs.GetNbVariables()
		fmt.Println("#cons:", ccs.GetNbConstraints(), nbInternal+nbSecret+nbPublic)
		fmt.Println("after compile, time elapsed from start:", time.Since(mainStart))
		//fmt.Println("size of ccs:", size.Of(ccs))
		//fmt.Println("time elapsed from start:", time.Since(mainStart))
		cccs = ccs.(*backend_bn254.R1CS)
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Lazify circuit, rebuild levels and dump lazy r1cs
	{
		fmt.Println("levels:", len(cccs.Levels))
		cccs.Lazify()

		ccsFile, err := os.Create("ccs.save")
		assert.NoError(err, "ccsFile")
		cnt, err := cccs.WriteTo(ccsFile)
		fmt.Println("written", cnt, " bytes to ccs.save")
		fmt.Println("after dump lazy ccs, time elapsed from start:", time.Since(mainStart))
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Solve wires on the lazified circuit

	// card := 1048576 // 2**20
	card := 268435456 // 2**28
	nbCons := cccs.GetNbConstraints() + cccs.LazyCons.GetConstraintsAll()
	a := make([]fr.Element, nbCons, card)
	b := make([]fr.Element, nbCons, card)
	c := make([]fr.Element, nbCons, card)

	opt, _ := backend.NewProverConfig()
	cccs.Solve(*witnessFull.Vector.(*witness_bn254.Witness), a, b, c, opt)
}

func TestE2ECompile(t *testing.T) {
	mainStart := time.Now()
	assert := test.NewAssert(t)

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Init operator and create witness
	var rollupCircuit Circuit
	{
		operator, users := createOperator(nbAccounts)
		sender, err := operator.readAccount(0)
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := operator.readAccount(1)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < batchSize; i++ {
			// create the transfer and sign it
			amount := uint64(0)
			transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce+uint64(i))

			// sign the transfer
			_, err = transfer.Sign(users[0], operator.h)
			if err != nil {
				t.Fatal(err)
			}
			err = operator.updateState(transfer, i)
			if err != nil {
				t.Fatal(err)
			}
		}
		witnessFull, err := frontend.NewWitness(&operator.witnesses, ecc.BN254)
		assert.NoError(err, "witnessFull")
		witnessPub, err := frontend.NewWitness(&operator.witnesses, ecc.BN254, frontend.PublicOnly())
		assert.NoError(err, "witnessPub")
		fmt.Println("Operator ready", time.Since(mainStart))

		witnessFullBytes, err := witnessFull.MarshalJSON()
		assert.NoError(err, "witnessFullBytes")
		err = os.WriteFile("witness_full.save", witnessFullBytes, 0666)
		assert.NoError(err, "write witness_full.save")
		fmt.Printf("Wrote %d bytes to witness_full.save\n", len(witnessFullBytes))

		witnessPubBytes, err := witnessPub.MarshalJSON()
		assert.NoError(err, "witnessPubBytes")
		err = os.WriteFile("witness_pub.save", witnessPubBytes, 0666)
		assert.NoError(err, "write witness_pub.save")
		fmt.Printf("Wrote %d bytes to witness_pub.save\n", len(witnessPubBytes))

	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Compile circuit
	cccs := &backend_bn254.R1CS{}
	{
		fmt.Println("Compile circuit", time.Since(mainStart))
		ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &rollupCircuit, frontend.IgnoreUnconstrainedInputs())
		assert.NoError(err, "compile")
		fmt.Println("NbCons:", ccs.GetNbConstraints())
		// fmt.Println("Size of ccs:", size.Of(ccs))
		cccs = ccs.(*backend_bn254.R1CS)
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Lazify circuit, rebuild levels and dump lazy r1cs
	{
		fmt.Println("Lazify circuit", time.Since(mainStart))
		cccs.Lazify()
		fmt.Println("Lazify circuit finished", time.Since(mainStart))
		fmt.Println("Size of cccs", size.Of(cccs))
		fmt.Printf("NbCons: %d, NbLazyCons: %d, NbLazyConsExpanded: %d\n", cccs.GetNbConstraints(),
			len(cccs.LazyCons), cccs.LazyCons.GetConstraintsAll())
		fmt.Println("#coefs:", len(cccs.CoefT.Coeffs), len(cccs.CoefT.CoeffsIDsInt64), len(cccs.CoefT.CoeffsIDsLarge))
		cTFile, err := os.Create("ccs.ct.save")
		assert.NoError(err, "ccs.ct.save")
		cnt, err := cccs.WriteCTTo(cTFile)
		assert.NoError(err, "write ccs.ct.save")
		fmt.Printf("....Wrote %d bytes to ccs.ct.save\n", cnt)
		cTFile.Close()
		// remove CoefT from cbor
		cccs.CoefT = cs.NewCoeffTable()

		ccsFile, err := os.Create("ccs.save")
		assert.NoError(err, "ccsFile")
		cnt, err = cccs.WriteTo(ccsFile)
		fmt.Printf("....Wrote %d bytes to ccs.save\n", cnt)
		ccsFile.Close()
	}

}

func TestE2ESetup(t *testing.T) {
	mainStart := time.Now()
	assert := test.NewAssert(t)
	session := "session1"

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Setup and dump pk, vk
	cccs := &backend_bn254.R1CS{}
	{
		ccsFile, err := os.Open("ccs.save")
		assert.NoError(err, "open ccsFile")
		cnt, err := cccs.ReadFrom(ccsFile)
		assert.NoError(err, "read cs")
		fmt.Printf("Read %d bytes from cccs.save\n", cnt)
		cTFile, err := os.Open("ccs.ct.save")
		assert.NoError(err, "open cTFile")
		cnt, err = cccs.ReadCTFrom(cTFile)
		assert.NoError(err, "read cs")
		fmt.Printf("Read %d bytes from cccs.ct.save\n", cnt)
	}
	{
		fmt.Printf("NbCons: %d, NbLazyCons: %d\n", cccs.GetNbConstraints(), len(cccs.LazyCons))
		err := groth16_bn254.SetupLazyWithDump(cccs, session)
		assert.NoError(err, "setup")
		fmt.Println("Finished setup", time.Since(mainStart))
	}
}

func TestE2EProve(t *testing.T) {
	mainStart := time.Now()
	assert := test.NewAssert(t)
	session := "session1"

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Read Lazy circuit and load pk
	cccs := &backend_bn254.R1CS{}
	var pkE, pkB2 groth16_bn254.ProvingKey
	var vk groth16_bn254.VerifyingKey
	{
		ccsFile, err := os.Open("ccs.save")
		assert.NoError(err, "open ccsFile")
		cnt, err := cccs.ReadFrom(ccsFile)
		assert.NoError(err, "read cs")
		fmt.Printf("Read %d bytes from cccs.save\n", cnt)
		ccsFile.Close()
		cTFile, err := os.Open("ccs.ct.save")
		assert.NoError(err, "open cTFile")
		cnt, err = cccs.ReadCTFrom(cTFile)
		assert.NoError(err, "read cs")
		fmt.Printf("Read %d bytes from cccs.ct.save\n", cnt)
		cTFile.Close()
		fmt.Println("Finished reading cs", time.Since(mainStart))
	}
	runtime.GC()
	{
		name := fmt.Sprintf("pk.E.%s.save", session)
		pkFile, err := os.Open(name)
		assert.NoError(err, "open pkFile")
		fmt.Println("size of pkE before read:", size.Of(pkE))
		cnt, err := pkE.UnsafeReadEFrom(pkFile)
		fmt.Println("size of pkE after read:", size.Of(pkE))
		fmt.Println("size of pkE after read:", len(pkE.InfinityB), size.Of(pkE.InfinityB), size.Of(pkE.InfinityA), size.Of(pkE.G1), size.Of(pkE.G2), size.Of(pkE.Domain))
		assert.NoError(err, "read pk.E")
		fmt.Printf("Read %d bytes from pk.E.save %v\n", cnt, time.Since(mainStart))
		pkFile.Close()

		name = fmt.Sprintf("pk.B2.%s.save", session)
		pkFile, err = os.Open(name)
		assert.NoError(err, "open pkFile")
		cnt, err = pkB2.UnsafeReadB2From(pkFile)
		assert.NoError(err, "read pk.B2")
		fmt.Printf("Read %d bytes from pk.B2.save %v\n", cnt, time.Since(mainStart))
		pkFile.Close()

		name = fmt.Sprintf("vk.%s.save", session)
		vkFile, err := os.Open(name)
		assert.NoError(err, "open vkFile")
		cnt, err = vk.UnsafeReadFrom(vkFile)
		assert.NoError(err, "read vk")
		fmt.Printf("Read %d bytes from vk.save %v\n", cnt, time.Since(mainStart))
		vkFile.Close()
	}
	runtime.GC()
	fmt.Println("domain card:", pkE.Card)
	// fmt.Println("size of cs:", size.Of(cccs)) // size.Of is slow
	// fmt.Println("size of pkE:", size.Of(pkE))
	// fmt.Println("size of pkB2:", size.Of(pkB2))

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Prove part by part
	witnessFull := &witness.Witness{CurveID: ecc.BN254, Schema: cccs.Schema}
	{
		wBytes, err := os.ReadFile("witness_full.save")
		assert.NoError(err, "read witness_full")
		json.Unmarshal(wBytes, &witnessFull)
	}
	opt, _ := backend.NewProverConfig()
	proof, err := groth16_bn254.ProveRoll(cccs, &pkE, &pkB2, *witnessFull.Vector.(*witness_bn254.Witness), opt, session)
	assert.NoError(err, "prove")
	fmt.Println("Finished proving", time.Since(mainStart))

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Verify proof
	witnessPub := &witness.Witness{CurveID: ecc.BN254, Schema: cccs.Schema}
	{
		wBytes, err := os.ReadFile("witness_pub.save")
		assert.NoError(err, "read witness_pub")
		json.Unmarshal(wBytes, &witnessPub)
	}
	err = groth16.Verify(proof, &vk, witnessPub)
	assert.NoError(err, "verify")
	fmt.Println("Finished verifying", time.Since(mainStart))
}

func TestE2EWhole(t *testing.T) {
	mainStart := time.Now()
	assert := test.NewAssert(t)
	session := "session1"

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Init operator and create witness
	var rollupCircuit Circuit
	var witnessFull, witnessPub *witness.Witness
	{
		operator, users := createOperator(nbAccounts)
		sender, err := operator.readAccount(0)
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := operator.readAccount(1)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < batchSize; i++ {
			// create the transfer and sign it
			amount := uint64(0)
			transfer := NewTransfer(amount, sender.pubKey, receiver.pubKey, sender.nonce+uint64(i))

			// sign the transfer
			_, err = transfer.Sign(users[0], operator.h)
			if err != nil {
				t.Fatal(err)
			}
			err = operator.updateState(transfer, i)
			if err != nil {
				t.Fatal(err)
			}
		}
		witnessFull, err = frontend.NewWitness(&operator.witnesses, ecc.BN254)
		assert.NoError(err, "witnessFull")
		witnessPub, err = frontend.NewWitness(&operator.witnesses, ecc.BN254, frontend.PublicOnly())
		assert.NoError(err, "witnessPub")
		fmt.Println("Operator ready", time.Since(mainStart), size.Of(witnessFull), size.Of(witnessPub))
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Compile circuit
	cccs := &backend_bn254.R1CS{}
	{
		fmt.Println("Compile circuit", time.Since(mainStart))
		ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &rollupCircuit, frontend.IgnoreUnconstrainedInputs())
		assert.NoError(err, "compile")
		fmt.Println("NbCons:", ccs.GetNbConstraints())
		// fmt.Println("Size of ccs:", size.Of(ccs))
		cccs = ccs.(*backend_bn254.R1CS)
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Lazify circuit, rebuild levels and dump lazy r1cs
	{
		cccs.Lazify()
	}

	{
		fmt.Printf("Lazy cs, NbCons: %d, NbLazyCons: %d\n", cccs.GetNbConstraints(), len(cccs.LazyCons))
		err := groth16_bn254.SetupLazyWithDump(cccs, session)
		assert.NoError(err, "setup")
		fmt.Println("Finished setup", time.Since(mainStart))
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Read Lazy circuit and load pk
	var pkE, pkB2 groth16_bn254.ProvingKey
	var vk groth16_bn254.VerifyingKey
	{
		name := fmt.Sprintf("pk.E.%s.save", session)
		pkFile, err := os.Open(name)
		assert.NoError(err, "open pkFile")
		fmt.Println("size of pkE before read:", size.Of(pkE))
		cnt, err := pkE.UnsafeReadEFrom(pkFile)
		fmt.Println("size of pkE after read:", size.Of(pkE))
		fmt.Println("size of pkE after read:", len(pkE.InfinityB), size.Of(pkE.InfinityB), size.Of(pkE.InfinityA), size.Of(pkE.G1), size.Of(pkE.G2), size.Of(pkE.Domain))
		assert.NoError(err, "read pk.E")
		fmt.Printf("Read %d bytes from pk.E.save %v\n", cnt, time.Since(mainStart))
		pkFile.Close()

		name = fmt.Sprintf("pk.B2.%s.save", session)
		pkFile, err = os.Open(name)
		assert.NoError(err, "open pkFile")
		cnt, err = pkB2.UnsafeReadB2From(pkFile)
		assert.NoError(err, "read pk.B2")
		fmt.Printf("Read %d bytes from pk.B2.save %v\n", cnt, time.Since(mainStart))
		pkFile.Close()

		name = fmt.Sprintf("vk.%s.save", session)
		vkFile, err := os.Open(name)
		assert.NoError(err, "open vkFile")
		cnt, err = vk.UnsafeReadFrom(vkFile)
		assert.NoError(err, "read vk")
		fmt.Printf("Read %d bytes from vk.save %v\n", cnt, time.Since(mainStart))
		vkFile.Close()
	}
	runtime.GC()
	fmt.Println("domain card:", pkE.Card)
	fmt.Println("size of cs:", size.Of(cccs)) //.R1CS.ConstraintSystem.MHints), size.Of(cccs.R1CS.ConstraintSystem))
	fmt.Println("size of pkE:", size.Of(pkE))
	fmt.Println("size of pkB2:", size.Of(pkB2))

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Prove part by part
	opt, _ := backend.NewProverConfig()
	proof, err := groth16_bn254.ProveRoll(cccs, &pkE, &pkB2, *witnessFull.Vector.(*witness_bn254.Witness), opt, session)
	assert.NoError(err, "prove")
	fmt.Println("Finished proving", time.Since(mainStart))

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Verify proof
	err = groth16.Verify(proof, &vk, witnessPub)
	assert.NoError(err, "verify")
	fmt.Println("Finished verifying", time.Since(mainStart))
}
