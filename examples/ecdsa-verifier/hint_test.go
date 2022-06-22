package ecdsa_verifier

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

type Circuit struct {
	PK frontend.Variable `gnark:"varY,public"`
	R  frontend.Variable
	S  frontend.Variable
}

// Verify(Sig) == True
// Need to add custom hint to verify the sig
// https://pkg.go.dev/github.com/consensys/gnark/backend/hint#hdr-Using_hint_functions_in_circuits
func (circuit *Circuit) Define(api frontend.API) error {
	res, _ := api.Compiler().NewHint(hint.IsZero, 1, circuit.R)
	isSigOK := res[0]
	api.AssertIsEqual(isSigOK, 0)
	return nil
}

func TestFoo(t *testing.T) {

	// Compile circuit
	var circuit Circuit
	_scs, _ := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	fmt.Println("Schema:", _scs.GetSchema())
	fmt.Println("SCs:", _scs.GetConstraints())

	srs, _ := test.NewKZGSRS(_scs)
	pk, vk, _ := plonk.Setup(_scs, srs)

	var w Circuit
	w.PK = 3
	w.S = 35
	w.R = 42

	witnessFull, _ := frontend.NewWitness(&w, ecc.BN254)
	proof, _ := plonk.Prove(_scs, pk, witnessFull)

	witnessPublic, _ := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
	err := plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)
}
