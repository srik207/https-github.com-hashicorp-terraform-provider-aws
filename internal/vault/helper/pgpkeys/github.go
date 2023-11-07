package pgpkeys

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/go-cleanhttp"
	"golang.org/x/crypto/openpgp"
	"io"
	"strings"
)

func FetchLatestGitHubPublicKey(pgpKey string) (string, error) {
	stringComponents := strings.Split(pgpKey, ":")
	if len(stringComponents) != 2 {
		return "", fmt.Errorf("invalid GPG key format for Github, received='%s', expected='github:$username'", pgpKey)
	}

	username := stringComponents[1]
	url := fmt.Sprintf("https://github.com/%s.gpg", username)
	resp, err := cleanhttp.DefaultClient().Get(url)

	if err != nil {
		return "", fmt.Errorf("retrieving Public Key from Github (%s): %w", pgpKey, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body containing GPG Public Key from GitHub")
	}

	bodyString := string(bodyBytes)
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(bodyString))
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

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
