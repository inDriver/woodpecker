package encrypted_secrets

import (
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
)

type keysetWatcher struct {
	encryption *Encryption
	watcher    *fsnotify.Watcher
}

// Watch keyset file events to detect key rotations and hot reload keys
func attachKeysetRotationWatcher(encryption *Encryption) {
	watcher := keysetWatcher{encryption, nil}
	watcher.initFileWatcher()
}

func (svc *keysetWatcher) initFileWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Err(err).Msgf("Error subscribing on encryption keyset file changes")
	}
	err = watcher.Add(svc.encryption.keysetFilePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error subscribing on encryption keyset file changes")
	}

	svc.watcher = watcher
	go svc.handleFileEvents()
}

func (svc *keysetWatcher) handleFileEvents() {
	for {
		select {
		case event, ok := <-svc.watcher.Events:
			if !ok {
				log.Fatal().Msg("Error watching encryption keyset file changes")
			}
			if (event.Op == fsnotify.Write) || (event.Op == fsnotify.Create) {
				log.Warn().Msgf("Changes detected in encryption keyset file: '%s'. Encryption service will be reloaded", event.Name)
				svc.encryption.initEncryption()
			}
		case err, ok := <-svc.watcher.Errors:
			if !ok {
				log.Fatal().Err(err).Msgf("Error watching encryption keyset file changes")
			}
		}
	}
}
