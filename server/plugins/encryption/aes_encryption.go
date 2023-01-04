// Copyright 2022 Woodpecker Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/sha3"

	"github.com/woodpecker-ci/woodpecker/server/store/types"
)

func (svc *aesEncryptionService) loadCipher(key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	svc.cipher = block
	svc.keyID, err = svc.hash(key)
	return err
}

func (svc *aesEncryptionService) validateKey() error {
	ciphertextSample, err := svc.store.ServerConfigGet(ciphertextSampleConfigKey)
	if errors.Is(err, types.RecordNotExist) {
		return errEncryptionNotEnabled
	} else if err != nil {
		return fmt.Errorf(errTemplateFailedLoadingServerConfig, err)
	}

	plaintext, err := svc.Decrypt(ciphertextSample, keyIDAssociatedData)
	if plaintext != svc.keyID {
		return errEncryptionKeyInvalid
	} else if err != nil {
		return err
	}
	return nil
}

func (svc *aesEncryptionService) hash(data []byte) (string, error) {
	result := make([]byte, 32)
	sha := sha3.NewShake256()

	_, err := sha.Write(data)
	if err != nil {
		return "", fmt.Errorf(errTemplateAesFailedCalculatingHash, err)
	}
	_, err = sha.Read(result)
	if err != nil {
		return "", fmt.Errorf(errTemplateAesFailedCalculatingHash, err)
	}
	return fmt.Sprintf("%x", result), nil
}

func (svc *aesEncryptionService) newSizeInfoChunk(dataLen int) (result []byte) {
	chainSize := svc.blockSize()
	result = make([]byte, chainSize)
	sl := []byte(
		strconv.FormatInt(int64(dataLen), 10),
	)
	noiseLen := chainSize - len(sl)

	for i := 0; i < noiseLen; i++ {
		result[i] = svc.getRandByteNaN()
	}
	copy(result[noiseLen:], sl)
	return
}

func (svc *aesEncryptionService) getRandByteNaN() byte {
	b := make([]byte, 1)
	for {
		if _, err := rand.Read(b[:1]); err != nil {
			panic(err) // newer happens
		}
		if b[0] < '0' || b[0] > '9' {
			return b[0]
		}
	}
}

func (svc *aesEncryptionService) alignDataByChainSize(data []byte) []byte {
	chainSize := svc.blockSize()
	resultChains := len(data) / chainSize
	if resultChains*chainSize < len(data) {
		// add some salt to last aesChain
		if len(data) > chainSize {
			addSz := len(data) - resultChains*chainSize
			data = append(data, data[len(data)-chainSize-addSz:len(data)-addSz]...)
		} else {
			addSz := chainSize - len(data)
			data = append(data, bytes.Repeat([]byte{data[0]}, addSz)...)
		}
	}
	return data
}

func (svc *aesEncryptionService) getDataSize(data []byte) (int, error) {
	chainSize := svc.blockSize()
	lenStart := 0
	for ; lenStart < chainSize; lenStart++ {
		if data[lenStart] >= '0' && data[lenStart] <= '9' {
			break
		}
	}
	dataLen, err := strconv.ParseInt(string(data[lenStart:chainSize]), 10, 64)
	if err != nil {
		return 0, err
	}
	return int(dataLen), nil
}

func (svc *aesEncryptionService) blockSize() int {
	return svc.cipher.BlockSize()
}

func (svc *aesEncryptionService) encode(dst, src []byte) (err error) {
	c := svc.newChain(src, dst)
	if err = c.mixInput(); err != nil {
		return
	}
	return c.encrypt(svc.cipher)
}

func (svc *aesEncryptionService) decode(dst, src []byte) (err error) {
	c := svc.newChain(src, dst)
	if err = c.decrypt(svc.cipher); err != nil {
		return
	}
	return c.mixOutput()
}

type aesChain struct {
	initV []byte
	inp   []byte
	out   []byte
	inter []byte
}

func (svc *aesEncryptionService) newChain(inp, out []byte) aesChain {
	return aesChain{
		initV: make([]byte, svc.blockSize()),
		inp:   inp,
		out:   out,
		inter: make([]byte, len(inp)),
	}
}

func (chain *aesChain) mixInput() error {
	return chain.xorData(chain.inp, chain.initV, chain.inter)
}

func (chain *aesChain) encrypt(crp interface{ Encrypt(dst, src []byte) }) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	crp.Encrypt(chain.out, chain.inter)
	return chain.xorData(chain.inp, chain.out, chain.initV)
}

func (chain *aesChain) decrypt(crp interface{ Decrypt(dst, src []byte) }) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	crp.Decrypt(chain.inter, chain.inp)
	return chain.xorData(chain.inter, chain.initV, chain.out)
}

func (chain *aesChain) mixOutput() error {
	return chain.xorData(chain.inp, chain.out, chain.initV)
}

func (chain *aesChain) xorData(a, b, c []byte) error {
	if len(a) != len(b) || len(b) != len(c) {
		return fmt.Errorf(errTemplateAesXorDifferentLenError, len(a), len(b), len(c))
	}
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return nil
}