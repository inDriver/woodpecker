package encrypted_secrets

import (
	"github.com/rs/zerolog/log"
	"github.com/woodpecker-ci/woodpecker/server/model"
	"strconv"
)

// Encrypt database after encryption was enabled
func (svc *Encryption) encryptDatabase() {
	log.Warn().Msg("Encrypting all secrets in database")
	for _, secret := range svc.fetchAllSecrets() {
		secret.Value = svc.decrypt(secret.Value, strconv.Itoa(int(secret.ID)))
		err := svc.store.SecretUpdate(secret)
		if err != nil {
			log.Fatal().Err(err).Msg("Secrets encryption failed: could not update secret in DB")
		}
	}
	log.Warn().Msg("All secrets are encrypted")
}

func (svc *Encryption) reEncryptDatabase() {
	log.Warn().Msg("Re-encrypting all secrets in database")
	for _, secret := range svc.fetchAllSecrets() {
		secret.Value = svc.decrypt(secret.Value, strconv.Itoa(int(secret.ID)))
		secret.Value = svc.encrypt(secret.Value, strconv.Itoa(int(secret.ID)))
		err := svc.store.SecretUpdate(secret)
		if err != nil {
			log.Fatal().Err(err).Msg("Secrets re-encryption failed: could not update secret in DB")
		}
	}
	log.Warn().Msg("All secrets are re-encrypted")
}

// Decrypt database and disable encryption in server config
func (svc *Encryption) decryptDatabase() {
	log.Warn().Msg("Decrypting all secrets")
	for _, secret := range svc.fetchAllSecrets() {
		secret.Value = svc.decrypt(secret.Value, strconv.Itoa(int(secret.ID)))
		err := svc.store.SecretUpdate(secret)
		if err != nil {
			log.Fatal().Err(err).Msg("Secrets decryption failed: could not update secret in DB")
		}
	}
	log.Warn().Msg("Secrets are decrypted")
}

func (svc *Encryption) fetchAllSecrets() []*model.Secret {
	secrets, err := svc.store.SecretListAll()
	if err != nil {
		log.Fatal().Err(err).Msg("Secrets decryption failed: could not fetch secrets from DB")
	}
	return secrets
}
