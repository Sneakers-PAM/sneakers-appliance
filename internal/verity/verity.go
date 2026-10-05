// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package verity computes and checks a dm-verity hash tree in pure Go,
// read-only: format 1 (veritysetup's default), SHA-256, 4096-byte data and
// hash blocks, with the superblock at the start of the hash area and the
// tree after it, top level first.
package verity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// BlockSize is the data and hash block size.
const BlockSize = 4096

const (
	superblockSize = 512
	hashesPerBlock = BlockSize / sha256.Size
	hashBits       = 7 // log2(hashesPerBlock)
)

var signature = [8]byte{'v', 'e', 'r', 'i', 't', 'y', 0, 0}

// ErrMismatch reports a tree that doesn't match the data, or a root hash
// other than the one expected.
var ErrMismatch = errors.New("verity: hash tree mismatch")

// Params are what the superblock records.
type Params struct {
	UUID       [16]byte
	DataBlocks uint64
	Salt       []byte
}

// Superblock is the on-disk struct verity_sb, 512 bytes.
type superblock struct {
	Signature     [8]byte
	Version       uint32
	HashType      uint32
	UUID          [16]byte
	Algorithm     [32]byte
	DataBlockSize uint32
	HashBlockSize uint32
	DataBlocks    uint64
	SaltSize      uint16
	Pad1          [6]byte
	Salt          [256]byte
	Pad2          [168]byte
}

// ReadParams reads the superblock at hashOffset and checks it describes
// the only format this package supports.
func ReadParams(r io.ReaderAt, hashOffset int64) (Params, error) {
	var raw [superblockSize]byte
	if _, err := r.ReadAt(raw[:], hashOffset); err != nil {
		return Params{}, fmt.Errorf("verity: read the superblock: %w", err)
	}
	var sb superblock
	if err := binary.Read(bytes.NewReader(raw[:]), binary.LittleEndian, &sb); err != nil {
		return Params{}, err
	}
	alg := string(bytes.TrimRight(sb.Algorithm[:], "\x00"))
	switch {
	case sb.Signature != signature:
		return Params{}, fmt.Errorf("verity: no superblock at offset %d", hashOffset)
	case sb.Version != 1 || sb.HashType != 1:
		return Params{}, fmt.Errorf("verity: superblock version %d hash type %d, want 1 and 1", sb.Version, sb.HashType)
	case alg != "sha256":
		return Params{}, fmt.Errorf("verity: algorithm %q, want sha256", alg)
	case sb.DataBlockSize != BlockSize || sb.HashBlockSize != BlockSize:
		return Params{}, fmt.Errorf("verity: block sizes %d and %d, want %d", sb.DataBlockSize, sb.HashBlockSize, BlockSize)
	case sb.SaltSize > 256:
		return Params{}, fmt.Errorf("verity: salt size %d", sb.SaltSize)
	case hashOffset <= 0 || sb.DataBlocks == 0 || sb.DataBlocks > uint64(hashOffset)/BlockSize: // #nosec G115 -- hashOffset is positive here
		return Params{}, fmt.Errorf("verity: %d data blocks don't fit before the hash area at %d", sb.DataBlocks, hashOffset)
	}
	return Params{UUID: sb.UUID, DataBlocks: sb.DataBlocks, Salt: append([]byte(nil), sb.Salt[:sb.SaltSize]...)}, nil
}

// levelBlocks returns the number of hash blocks at each level, level 0 (the
// hashes of the data blocks) first. The last level has one block.
func levelBlocks(dataBlocks uint64) []uint64 {
	levels := 0
	for hashBits*levels < 64 && (dataBlocks-1)>>(hashBits*uint(levels)) != 0 {
		levels++
	}
	out := make([]uint64, levels)
	for i := range out {
		shift := uint(hashBits * (i + 1))
		out[i] = (dataBlocks + (1 << shift) - 1) >> shift
	}
	return out
}

func hashBlock(salt, block []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(block)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// tree computes every level of the tree and the root hash.
func tree(r io.ReaderAt, p Params) (levels [][]byte, root [sha256.Size]byte, err error) {
	sizes := levelBlocks(p.DataBlocks)
	buf := make([]byte, BlockSize)
	if len(sizes) == 0 {
		if _, err := r.ReadAt(buf, 0); err != nil {
			return nil, root, err
		}
		return nil, hashBlock(p.Salt, buf), nil
	}
	// Level 0 from the data blocks.
	cur := make([]byte, sizes[0]*BlockSize)
	for i := uint64(0); i < p.DataBlocks; i++ {
		if _, err := r.ReadAt(buf, int64(i)*BlockSize); err != nil {
			return nil, root, fmt.Errorf("verity: read data block %d: %w", i, err)
		}
		h := hashBlock(p.Salt, buf)
		copy(cur[i*sha256.Size:], h[:])
	}
	levels = append(levels, cur)
	for lv := 1; lv < len(sizes); lv++ {
		prev := levels[lv-1]
		next := make([]byte, sizes[lv]*BlockSize)
		for i := 0; i*BlockSize < len(prev); i++ {
			h := hashBlock(p.Salt, prev[i*BlockSize:(i+1)*BlockSize])
			copy(next[i*sha256.Size:], h[:])
		}
		levels = append(levels, next)
	}
	top := levels[len(levels)-1]
	return levels, hashBlock(p.Salt, top[:BlockSize]), nil
}

// HashArea returns the bytes of the hash area for data: the superblock in
// its own block, then the levels, top level first.
func HashArea(r io.ReaderAt, p Params) (area []byte, root [sha256.Size]byte, err error) {
	levels, root, err := tree(r, p)
	if err != nil {
		return nil, root, err
	}
	var sb bytes.Buffer
	s := superblock{Signature: signature, Version: 1, HashType: 1, UUID: p.UUID,
		DataBlockSize: BlockSize, HashBlockSize: BlockSize, DataBlocks: p.DataBlocks, SaltSize: uint16(len(p.Salt))} // #nosec G115 -- ReadParams and Format bound the salt to 256 bytes
	copy(s.Algorithm[:], "sha256")
	copy(s.Salt[:], p.Salt)
	if err := binary.Write(&sb, binary.LittleEndian, s); err != nil {
		return nil, root, err
	}
	area = append(sb.Bytes(), make([]byte, BlockSize-superblockSize)...)
	for i := len(levels) - 1; i >= 0; i-- {
		area = append(area, levels[i]...)
	}
	return area, root, nil
}

// RootHash reads the superblock at hashOffset, recomputes the tree over the
// data before it, checks the stored tree equals the recomputed one, and
// returns the root hash. size is the whole image's size.
func RootHash(r io.ReaderAt, size, hashOffset int64) ([]byte, error) {
	if hashOffset <= 0 || hashOffset%BlockSize != 0 || hashOffset >= size {
		return nil, fmt.Errorf("verity: hash offset %d doesn't fit an image of %d bytes", hashOffset, size)
	}
	p, err := ReadParams(r, hashOffset)
	if err != nil {
		return nil, err
	}
	want, root, err := HashArea(r, p)
	if err != nil {
		return nil, err
	}
	if hashOffset+int64(len(want)) > size {
		return nil, fmt.Errorf("%w: the image ends before the hash tree does", ErrMismatch)
	}
	got := make([]byte, len(want))
	if _, err := r.ReadAt(got, hashOffset); err != nil {
		return nil, err
	}
	if !bytes.Equal(got, want) {
		return nil, fmt.Errorf("%w: the stored tree doesn't match the data", ErrMismatch)
	}
	return root[:], nil
}

// Format computes the hash area for dataSize bytes of data (a multiple of
// BlockSize) with a fresh random salt and UUID, as `veritysetup format`
// does, and returns it with the root hash.
func Format(r io.ReaderAt, dataSize int64) (area []byte, root []byte, err error) {
	if dataSize <= 0 || dataSize%BlockSize != 0 {
		return nil, nil, fmt.Errorf("verity: data size %d isn't a positive multiple of %d", dataSize, BlockSize)
	}
	p := Params{DataBlocks: uint64(dataSize / BlockSize), Salt: make([]byte, 32)}
	if _, err := rand.Read(p.Salt); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(p.UUID[:]); err != nil {
		return nil, nil, err
	}
	p.UUID[6] = p.UUID[6]&0x0f | 0x40
	p.UUID[8] = p.UUID[8]&0x3f | 0x80
	area, rh, err := HashArea(r, p)
	return area, rh[:], err
}
