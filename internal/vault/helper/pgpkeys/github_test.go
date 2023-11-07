package pgpkeys

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"reflect"
	"testing"
)

func TestFetchLatestGitHubPublicKey(t *testing.T) {
	t.Parallel()

	testuser := "github:chomatdam"
	ret, err := FetchLatestGitHubPublicKey(testuser)
	if err != nil {
		t.Fatalf("bad: %v", err)
	}

	fingerprints := []string{}
	data, err := base64.StdEncoding.DecodeString(ret)
	if err != nil {
		t.Fatalf("error decoding key for user %s: %v", testuser, err)
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(data)))
	if err != nil {
		t.Fatalf("error parsing key for user %s: %v", testuser, err)
	}
	fingerprints = append(fingerprints, hex.EncodeToString(entity.PrimaryKey.Fingerprint[:]))

	exp := "c4df834a8627a6dcc0f0d94f8481f3143070234d"

	if !reflect.DeepEqual(fingerprints, exp) {
		t.Fatalf("fingerprints do not match; expected \n%#v\ngot\n%#v\n", exp, fingerprints)
	}
}
