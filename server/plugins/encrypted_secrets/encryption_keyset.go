package encrypted_secrets

import (
	"errors"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/rs/zerolog/log"
	"github.com/woodpecker-ci/woodpecker/server/store/datastore"
	"os"
	"strconv"
)

// Init and hot reload encryption primitive
func (svc *Encryption) initEncryption() {
	log.Warn().Msg("Loading secrets encryption keyset")
	file, err := os.Open(svc.keysetFilePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error opening secret encryption keyset file")
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	jsonKeyset := keyset.NewJSONReader(file)
	keysetHandle, err := insecurecleartextkeyset.Read(jsonKeyset)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error reading secret encryption keyset")
	}
	svc.primaryKeyId = strconv.FormatUint(uint64(keysetHandle.KeysetInfo().PrimaryKeyId), 10)

	encryptionInstance, err := daead.New(keysetHandle)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error initializing secret encryption")
	}
	svc.encryption = encryptionInstance

	svc.validateKeyset()
}

// DB ciphertext sample
// store encrypted primaryKeyId in DB to check if used keyset is the same as used to encrypt secrets data
// and to detect keyset rotations
func (svc *Encryption) validateKeyset() {
	ciphertextSample, err := svc.store.ServerConfigGet("secrets-encryption-key-id")
	if errors.Is(err, datastore.RecordNotExist) {
		svc.updateCiphertextSample()
		log.Warn().Msg("Secrets encryption enabled on server")
		return
	} else if err != nil {
		log.Fatal().Err(err).Msgf("Invalid secrets encryption key")
	}

	aad := "Primary key id"
	plaintext := svc.decrypt(ciphertextSample, aad)
	if err != nil {
		log.Fatal().Err(err).Msgf("Secrets encryption error")
	} else if plaintext != svc.primaryKeyId {
		svc.updateCiphertextSample()
		log.Info().Msg("Registered rotated secrets encryption key")
	}
}

func (svc *Encryption) updateCiphertextSample() {
	aad := "Primary key id"
	ct := svc.encrypt(svc.primaryKeyId, aad)

	err := svc.store.ServerConfigSet("secrets-encryption-key-id", ct)
	if err != nil {
		log.Fatal().Err(err).Msgf("Storage error")
	}
}