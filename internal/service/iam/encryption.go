// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iam

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/terraform-provider-aws/internal/vault/helper/pgpkeys"
	"golang.org/x/crypto/openpgp"
	"net/http"
	"strings"
)

// retrieveGPGKey returns the PGP key specified as the pgpKey parameter, or queries
// the public key from the keybase service if the parameter is a keybase username
// prefixed with the phrase "keybase:"
func retrieveGPGKey(pgpKey string) (string, error) {
	const keybasePrefix = "keybase:"
	const githubPrefix = "github:"

	encryptionKey := pgpKey
	if strings.HasPrefix(pgpKey, keybasePrefix) {
		publicKeys, err := pgpkeys.FetchKeybasePubkeys([]string{pgpKey})
		if err != nil {
			return "", fmt.Errorf("retrieving Unarmored (Raw) Public Key from Keybase (%s): %w", pgpKey, err)
		}
		encryptionKey = publicKeys[pgpKey]
	} else if strings.HasPrefix(pgpKey, githubPrefix) {
		stringComponents := strings.Split(pgpKey, ":")
		if len(stringComponents) != 2 {
			return "", fmt.Errorf("invalid GPG key format for Github, received='%s', expected='github:$username'", pgpKey)
		}

		url := fmt.Sprintf("https://github.com/%s.gpg", stringComponents[1])
		resp, err := http.Get(url)

		if err != nil {
			return "", fmt.Errorf("retrieving Armored (ASCII) Public Key from Github (%s): %w", pgpKey, err)
		}
		defer resp.Body.Close()

		keyring, err := openpgp.ReadArmoredKeyRing(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error reading keyring: %w", err)
		}
		if len(keyring) < 1 {
			return "", fmt.Errorf("no key found in keyring")
		}

		var buf bytes.Buffer
		err = keyring[0].Serialize(&buf)
		if err != nil {
			return "", fmt.Errorf("serialize first GitHub GPG Key from keyring: %w", err)
		}
		encryptionKey = base64.StdEncoding.EncodeToString(buf.Bytes())
	}

	return encryptionKey, nil
}

// encryptValue encrypts the given value with the given encryption key. Description
// should be set such that errors return a meaningful user-facing response.
func encryptValue(encryptionKey, value, description string) (string, string, error) {
	fingerprints, encryptedValue, err :=
		pgpkeys.EncryptShares([][]byte{[]byte(value)}, []string{encryptionKey})
	if err != nil {
		return "", "", fmt.Errorf("encrypting %s: %w", description, err)
	}

	return fingerprints[0], base64.StdEncoding.EncodeToString(encryptedValue[0]), nil
}
