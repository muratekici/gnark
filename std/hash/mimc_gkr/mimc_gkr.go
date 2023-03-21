package mimc_gkr

import (
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

func NewMimcWithGKR(api frontend.API, il, ir frontend.Variable) frontend.Variable {
	il = api.Add(il, ir)
	results, err := api.Compiler().NewHint(hint.MIMC2Elements, 1, il, ir)
	if err != nil {
		panic(err)
	}

	return results[0]
}
