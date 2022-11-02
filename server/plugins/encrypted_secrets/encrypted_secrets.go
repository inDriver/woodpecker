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

package encrypted_secrets

import (
	"github.com/urfave/cli/v2"
	"github.com/woodpecker-ci/woodpecker/server/model"
	"github.com/woodpecker-ci/woodpecker/server/plugins/secrets"
	"github.com/woodpecker-ci/woodpecker/server/store"
)

// wraps secret service and adds encryption to values
type builtin struct {
	encryption Encryption
	secrets    model.SecretService
	store      store.Store
}

// New returns a new local secret service with encrypted secret storage
func New(c *cli.Context, s store.Store) model.SecretService {
	encryption := newEncryptionService(c, s)
	secretsService := secrets.New(c.Context, s)
	attachKeysetRotationWatcher(&encryption)

	return &builtin{encryption, secretsService, s}
}

func (b *builtin) SecretFind(repo *model.Repo, name string) (*model.Secret, error) {
	result, err := b.secrets.SecretFind(repo, name)
	if err != nil {
		return nil, err
	}
	b.encryption.decryptSecret(result)
	return result, nil
}

func (b *builtin) SecretList(repo *model.Repo) ([]*model.Secret, error) {
	result, err := b.secrets.SecretList(repo)
	if err != nil {
		return nil, err
	}
	b.encryption.decryptSecretList(result)
	return result, nil
}

func (b *builtin) SecretListBuild(repo *model.Repo, build *model.Build) ([]*model.Secret, error) {
	result, err := b.secrets.SecretListBuild(repo, build)
	if err != nil {
		return nil, err
	}
	b.encryption.decryptSecretList(result)
	return result, nil
}

func (b *builtin) SecretCreate(repo *model.Repo, in *model.Secret) error {
	b.encryption.encryptSecret(in)
	return b.secrets.SecretCreate(repo, in)
}

func (b *builtin) SecretUpdate(repo *model.Repo, in *model.Secret) error {
	b.encryption.encryptSecret(in)
	return b.secrets.SecretUpdate(repo, in)
}

func (b *builtin) SecretDelete(repo *model.Repo, name string) error {
	return b.secrets.SecretDelete(repo, name)
}

// internals
