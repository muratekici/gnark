package circuits

import (
	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

const bound = 44

type rangeCheckConstantCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *rangeCheckConstantCircuit) Define(api frontend.API) error {
	c1 := api.Mul(circuit.X, circuit.Y)
	c2 := api.Mul(c1, circuit.Y)
	c3 := api.Add(circuit.X, circuit.Y)
	api.AssertIsLessOrEqual(c3, bound) // c3 is from a linear expression only
	api.AssertIsLessOrEqual(c2, bound)
	return nil
}

func rangeCheckConstant() {
	var circuit, good, bad rangeCheckConstantCircuit

	good.X = (4)
	good.Y = (2)

	bad.X = (11)
	bad.Y = (4)

	addEntry("range_constant", &circuit, &good, &bad, gnark.Curves())
}

type rangeCheckCircuit struct {
	X        frontend.Variable
	Y, Bound frontend.Variable `gnark:",public"`
}

// Define in order to avoid overflow, we refactor the range check
func (circuit *rangeCheckCircuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(circuit.X, circuit.Bound)
	api.AssertIsLessOrEqual(circuit.Y, circuit.Bound)

	return nil
}

func rangeCheck() {

	var circuit, good, bad rangeCheckCircuit

	good.X = (4)
	good.Y = (2)
	good.Bound = (bound)

	bad.X = (11)
	bad.Y = (4)
	bad.Bound = (bound)

	addEntry("range", &circuit, &good, &bad, []ecc.ID{ecc.BN254})
}

func init() {
	rangeCheckConstant()
	rangeCheck()
}
