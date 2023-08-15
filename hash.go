// Copyright © 2019 Weald Technology Trading
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

package merkletree

import (
	"fmt"

	"github.com/MetaDataLab/go-merkletree/blake2b"
	"github.com/MetaDataLab/go-merkletree/keccak256"
	"github.com/MetaDataLab/go-merkletree/sha3"
)

// HashFunc is a hashing function.
type HashFunc func(...[]byte) []byte

// HashType defines the interface that must be supplied by hash functions.
type HashType interface {
	// Hash calculates the hash of a given input.
	Hash(...[]byte) []byte

	// HashLength provides the length of the hash.
	HashLength() int
}

type HashCode int

const (
	INVALID   HashCode = iota // 0
	BLAKE2B                   // 1
	KECCAK256                 // 2
	SHA256                    // 3
	SHA512                    // 4
)

func GetHashCode(value HashType) (HashCode, error) {
	switch value.(type) {
	case *blake2b.BLAKE2b:
		return BLAKE2B, nil
	case *keccak256.Keccak256:
		return KECCAK256, nil
	case *sha3.SHA256:
		return SHA256, nil
	case *sha3.SHA512:
		return SHA512, nil
	default:
		return INVALID, fmt.Errorf("invalid hash type")
	}
}

func GetHashTypeFromCode(code HashCode) (HashType, error) {
	switch code {
	case BLAKE2B:
		return blake2b.New(), nil
	case KECCAK256:
		return keccak256.New(), nil
	case SHA256:
		return sha3.New256(), nil
	case SHA512:
		return sha3.New512(), nil
	default:
		return nil, fmt.Errorf("invalid hash code: %v", code)
	}
}
