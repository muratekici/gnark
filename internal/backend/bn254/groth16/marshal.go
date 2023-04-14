// Copyright 2020 ConsenSys Software Inc.
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

// Code generated by gnark DO NOT EDIT

package groth16

import (
	"encoding/gob"
	"fmt"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"io"
	"os"
)

// WriteTo writes binary encoding of the Proof elements to writer
// points are stored in compressed form Ar | Krs | Bs
// use WriteRawTo(...) to encode the proof without point compression
func (proof *Proof) WriteTo(w io.Writer) (n int64, err error) {
	return proof.writeTo(w, false)
}

// WriteRawTo writes binary encoding of the Proof elements to writer
// points are stored in uncompressed form Ar | Krs | Bs
// use WriteTo(...) to encode the proof with point compression
func (proof *Proof) WriteRawTo(w io.Writer) (n int64, err error) {
	return proof.writeTo(w, true)
}

func (proof *Proof) writeTo(w io.Writer, raw bool) (int64, error) {
	var enc *curve.Encoder
	if raw {
		enc = curve.NewEncoder(w, curve.RawEncoding())
	} else {
		enc = curve.NewEncoder(w)
	}

	if err := enc.Encode(&proof.Ar); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&proof.Bs); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&proof.Krs); err != nil {
		return enc.BytesWritten(), err
	}
	return enc.BytesWritten(), nil
}

// ReadFrom attempts to decode a Proof from reader
// Proof must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed)
func (proof *Proof) ReadFrom(r io.Reader) (n int64, err error) {

	dec := curve.NewDecoder(r)

	if err := dec.Decode(&proof.Ar); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&proof.Bs); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&proof.Krs); err != nil {
		return dec.BytesRead(), err
	}

	return dec.BytesRead(), nil
}

// WriteTo writes binary encoding of the key elements to writer
// points are compressed
// use WriteRawTo(...) to encode the key without point compression
func (vk *VerifyingKey) WriteTo(w io.Writer) (n int64, err error) {
	return vk.writeTo(w, false)
}

// WriteRawTo writes binary encoding of the key elements to writer
// points are not compressed
// use WriteTo(...) to encode the key with point compression
func (vk *VerifyingKey) WriteRawTo(w io.Writer) (n int64, err error) {
	return vk.writeTo(w, true)
}

// writeTo serialization format:
// follows bellman format:
// https://github.com/zkcrypto/bellman/blob/fa9be45588227a8c6ec34957de3f68705f07bd92/src/groth16/mod.rs#L143
// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2,uint32(len(Kvk)),[Kvk]1
func (vk *VerifyingKey) writeTo(w io.Writer, raw bool) (int64, error) {
	n, err := vk.CommitmentKey.WriteTo(w)
	if err != nil {
		return n, err
	}

	var enc *curve.Encoder
	if raw {
		enc = curve.NewEncoder(w, curve.RawEncoding())
	} else {
		enc = curve.NewEncoder(w)
	}

	// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2
	if err := enc.Encode(&vk.G1.Alpha); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Beta); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Beta); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Gamma); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Delta); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Delta); err != nil {
		return n + enc.BytesWritten(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := enc.Encode(vk.G1.K); err != nil {
		return n + enc.BytesWritten(), err
	}

	encGob := gob.NewEncoder(w)
	if err := encGob.Encode(vk.CommitmentInfo); err != nil {
		return n + enc.BytesWritten(), err
	}
	return n + enc.BytesWritten(), nil
}

// ReadFrom attempts to decode a VerifyingKey from reader
// VerifyingKey must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed)
// serialization format:
// https://github.com/zkcrypto/bellman/blob/fa9be45588227a8c6ec34957de3f68705f07bd92/src/groth16/mod.rs#L143
// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2,uint32(len(Kvk)),[Kvk]1
func (vk *VerifyingKey) ReadFrom(r io.Reader) (int64, error) {
	return vk.readFrom(r)
}

// UnsafeReadFrom has the same behavior as ReadFrom, except that it will not check that decode points
// are on the curve and in the correct subgroup.
func (vk *VerifyingKey) UnsafeReadFrom(r io.Reader) (int64, error) {
	return vk.readFrom(r, curve.NoSubgroupChecks())
}

func (vk *VerifyingKey) readFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	n, err := vk.CommitmentKey.ReadFrom(r, decOptions...)
	if err != nil {
		return n, err
	}
	dec := curve.NewDecoder(r, decOptions...)

	// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2
	if err := dec.Decode(&vk.G1.Alpha); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G1.Beta); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G2.Beta); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G2.Gamma); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G1.Delta); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&vk.G2.Delta); err != nil {
		return n + dec.BytesRead(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := dec.Decode(&vk.G1.K); err != nil {
		return n + dec.BytesRead(), err
	}

	decGob := gob.NewDecoder(r)
	if err := decGob.Decode(&vk.CommitmentInfo); err != nil {
		return n + dec.BytesRead(), err
	}
	// recompute vk.e (e(α, β)) and  -[δ]2, -[γ]2
	vk.e, err = curve.Pair([]curve.G1Affine{vk.G1.Alpha}, []curve.G2Affine{vk.G2.Beta})
	if err != nil {
		return n + dec.BytesRead(), err
	}
	vk.G2.deltaNeg.Neg(&vk.G2.Delta)
	vk.G2.gammaNeg.Neg(&vk.G2.Gamma)

	return n + dec.BytesRead(), nil
}

// WriteTo writes binary encoding of the key elements to writer
// points are compressed
// use WriteRawTo(...) to encode the key without point compression
func (pk *ProvingKey) WriteTo(w io.Writer) (n int64, err error) {
	return pk.writeTo(w, false)
}

func (pk *ProvingKey) DumpSegmented(session string) (n int64, err error) {
	// E part
	{
		name := fmt.Sprintf("%s.pk.E.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return n, err
		}
		n_, err := pk.WriteRawETo(pkFile)
		if err != nil {
			return n, err
		}
		n += n_
	}

	// A part
	{
		name := fmt.Sprintf("%s.pk.A.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return n, err
		}
		n_, err := pk.WriteRawATo(pkFile)
		if err != nil {
			return n, err
		}
		n += n_
	}

	// B1 part
	{
		name := fmt.Sprintf("%s.pk.B1.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return n, err
		}
		n_, err := pk.WriteRawB1To(pkFile)
		if err != nil {
			return n, err
		}
		n += n_
	}

	// K part
	{
		name := fmt.Sprintf("%s.pk.K.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return n, err
		}
		n_, err := pk.WriteRawKTo(pkFile)
		if err != nil {
			return n, err
		}
		n += n_
	}

	// Z part
	{
		name := fmt.Sprintf("%s.pk.Z.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return n, err
		}
		n_, err := pk.WriteRawZTo(pkFile)
		if err != nil {
			return n, err
		}
		n += n_
	}

	// B2 part
	{
		name := fmt.Sprintf("%s.pk.B2.save", session)
		pkFile, err := os.Create(name)
		if err != nil {
			return n, err
		}
		n_, err := pk.WriteRawB2To(pkFile)
		if err != nil {
			return n, err
		}
		n += n_
	}
	return n, err
}

// WriteRawTo writes binary encoding of the key elements to writer
// points are not compressed
// use WriteTo(...) to encode the key with point compression
func (pk *ProvingKey) WriteRawTo(w io.Writer) (n int64, err error) {
	return pk.writeTo(w, true)
}

func (pk *ProvingKey) WriteRawETo(w io.Writer) (n int64, err error) {
	return pk.writeETo(w)
}

func (pk *ProvingKey) WriteRawCommitmentKeyTo(w io.Writer) (n int64, err error) {
	return pk.CommitmentKey.WriteTo(w)
}

func (pk *ProvingKey) WriteRawATo(w io.Writer) (n int64, err error) {
	return pk.writeATo(w)
}

func (pk *ProvingKey) WriteRawB1To(w io.Writer) (n int64, err error) {
	return pk.writeB1To(w)
}

func (pk *ProvingKey) WriteRawB2To(w io.Writer) (n int64, err error) {
	return pk.writeB2To(w)
}

func (pk *ProvingKey) WriteRawZTo(w io.Writer) (n int64, err error) {
	return pk.writeZTo(w)
}

func (pk *ProvingKey) WriteRawKTo(w io.Writer) (n int64, err error) {
	return pk.writeKTo(w)
}

func (pk *ProvingKey) writeTo(w io.Writer, raw bool) (int64, error) {
	n, err := pk.Domain.WriteTo(w)
	if err != nil {
		return n, err
	}

	var enc *curve.Encoder
	if raw {
		enc = curve.NewEncoder(w, curve.RawEncoding())
	} else {
		enc = curve.NewEncoder(w)
	}
	nbWires := uint64(len(pk.InfinityA))

	toEncode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		pk.G1.A,
		pk.G1.B,
		pk.G1.Z,
		pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		pk.G2.B,
		nbWires,
		pk.NbInfinityA,
		pk.NbInfinityB,
		pk.InfinityA,
		pk.InfinityB,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return n + enc.BytesWritten(), err
		}
	}

	return n + enc.BytesWritten(), nil

}

func (pk *ProvingKey) writeETo(w io.Writer) (int64, error) {
	var enc = curve.NewEncoder(w, curve.RawEncoding())
	nbWires := uint64(len(pk.InfinityA))

	toEncode := []interface{}{
		&pk.Domain.Cardinality,
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		//pk.G1.A,
		//pk.G1.B,
		//pk.G1.Z,
		//pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		//pk.G2.B,
		nbWires,
		pk.NbInfinityA,
		pk.NbInfinityB,
		pk.InfinityA,
		pk.InfinityB,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil

}

func (pk *ProvingKey) writeATo(w io.Writer) (int64, error) {
	var enc = curve.NewEncoder(w, curve.RawEncoding())

	toEncode := []interface{}{
		pk.G1.A,
		//pk.G1.B,
		//pk.G1.Z,
		//pk.G1.K,
		//pk.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil

}

func (pk *ProvingKey) writeB1To(w io.Writer) (int64, error) {
	var enc = curve.NewEncoder(w, curve.RawEncoding())

	toEncode := []interface{}{
		//pk.G1.A,
		pk.G1.B,
		//pk.G1.Z,
		//pk.G1.K,
		//pk.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil

}

func (pk *ProvingKey) writeB2To(w io.Writer) (int64, error) {
	var enc = curve.NewEncoder(w, curve.RawEncoding())

	toEncode := []interface{}{
		//pk.G1.A,
		//pk.G1.B,
		//pk.G1.Z,
		//pk.G1.K,
		pk.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil

}

func (pk *ProvingKey) writeZTo(w io.Writer) (int64, error) {
	var enc = curve.NewEncoder(w, curve.RawEncoding())

	toEncode := []interface{}{
		//pk.G1.A,
		//pk.G1.B,
		pk.G1.Z,
		//pk.G1.K,
		//pk.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil

}

func (pk *ProvingKey) writeKTo(w io.Writer) (int64, error) {
	var enc = curve.NewEncoder(w, curve.RawEncoding())

	toEncode := []interface{}{
		//pk.G1.A,
		//pk.G1.B,
		//pk.G1.Z,
		pk.G1.K,
		//pk.G2.B,
	}

	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}

	return enc.BytesWritten(), nil

}

// ReadFrom attempts to decode a ProvingKey from reader
// ProvingKey must be encoded through WriteTo (compressed) or WriteRawTo (uncompressed)
// note that we don't check that the points are on the curve or in the correct subgroup at this point
func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {
	return pk.readFrom(r)
}

// UnsafeReadFrom behaves like ReadFrom excepts it doesn't check if the decoded points are on the curve
// or in the correct subgroup
func (pk *ProvingKey) UnsafeReadFrom(r io.Reader) (int64, error) {
	return pk.readFrom(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) UnsafeReadEFrom(r io.Reader) (int64, error) {
	return pk.readEFrom(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) UnsafeReadCommitmentKeyFrom(r io.Reader) (int64, error) {
	return pk.CommitmentKey.ReadFrom(r)
}

func (pk *ProvingKey) UnsafeReadAFrom(r io.Reader) (int64, error) {
	return pk.readAFrom(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) UnsafeReadB1From(r io.Reader) (int64, error) {
	return pk.readB1From(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) UnsafeReadB2From(r io.Reader) (int64, error) {
	return pk.readB2From(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) UnsafeReadZFrom(r io.Reader) (int64, error) {
	return pk.readZFrom(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) UnsafeReadKFrom(r io.Reader) (int64, error) {
	return pk.readKFrom(r, curve.NoSubgroupChecks())
}

func (pk *ProvingKey) readFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	n, err := pk.Domain.ReadFrom(r)
	if err != nil {
		return n, err
	}

	dec := curve.NewDecoder(r, decOptions...)

	var nbWires uint64

	toDecode := []interface{}{
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		&pk.G1.A,
		&pk.G1.B,
		&pk.G1.Z,
		&pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		&pk.G2.B,
		&nbWires,
		&pk.NbInfinityA,
		&pk.NbInfinityB,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return n + dec.BytesRead(), err
		}
	}
	pk.InfinityA = make([]bool, nbWires)
	pk.InfinityB = make([]bool, nbWires)

	if err := dec.Decode(&pk.InfinityA); err != nil {
		return n + dec.BytesRead(), err
	}
	if err := dec.Decode(&pk.InfinityB); err != nil {
		return n + dec.BytesRead(), err
	}

	return n + dec.BytesRead(), nil
}

func (pk *ProvingKey) readEFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)

	var nbWires uint64

	toDecode := []interface{}{
		&pk.Card,
		&pk.G1.Alpha,
		&pk.G1.Beta,
		&pk.G1.Delta,
		//&pk.G1.A,
		//&pk.G1.B,
		//&pk.G1.Z,
		//&pk.G1.K,
		&pk.G2.Beta,
		&pk.G2.Delta,
		//&pk.G2.B,
		&nbWires,
		&pk.NbInfinityA,
		&pk.NbInfinityB,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}
	pk.InfinityA = make([]bool, nbWires)
	pk.InfinityB = make([]bool, nbWires)

	if err := dec.Decode(&pk.InfinityA); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&pk.InfinityB); err != nil {
		return dec.BytesRead(), err
	}

	return dec.BytesRead(), nil
}

func (pk *ProvingKey) readAFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)

	toDecode := []interface{}{
		&pk.G1.A,
		//&pk.G1.B,
		//&pk.G1.Z,
		//&pk.G1.K,
		//&pk.G2.B,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}

func (pk *ProvingKey) readB1From(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)

	toDecode := []interface{}{
		//&pk.G1.A,
		&pk.G1.B,
		//&pk.G1.Z,
		//&pk.G1.K,
		//&pk.G2.B,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}

func (pk *ProvingKey) readB2From(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)

	toDecode := []interface{}{
		//&pk.G1.A,
		//&pk.G1.B,
		//&pk.G1.Z,
		//&pk.G1.K,
		&pk.G2.B,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}

func (pk *ProvingKey) readZFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)

	toDecode := []interface{}{
		//&pk.G1.A,
		//&pk.G1.B,
		&pk.G1.Z,
		//&pk.G1.K,
		//&pk.G2.B,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}

func (pk *ProvingKey) readKFrom(r io.Reader, decOptions ...func(*curve.Decoder)) (int64, error) {
	dec := curve.NewDecoder(r, decOptions...)

	toDecode := []interface{}{
		//&pk.G1.A,
		//&pk.G1.B,
		//&pk.G1.Z,
		&pk.G1.K,
		//&pk.G2.B,
	}

	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}

	return dec.BytesRead(), nil
}
