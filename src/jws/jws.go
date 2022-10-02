package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	keyType   = "RSA"
	algorithm = "RS256" // 2048 RSA key, maybe move generated bits and this constant into globals TODO
)

// According to RFC 8555 - Automatic Certificate Management Environment (ACME)
// See https://www.rfc-editor.org/rfc/rfc8555#section-6.2
type JWS struct {
	Header    string `json:"protected,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type JWSProtectedHeader struct {
	Alg   string `json:"alg,omitempty"`   // This field MUST NOT contain "none" or a Message Authentication Code (MAC) algorithm (e.g. one in which the algorithm registry description mentions MAC/HMAC)
	Nonce string `json:"nonce,omitempty"` // nonce
	URL   string `json:"url,omitempty"`   // URL to the account used
	JWK   JWK    `json:"jwk,omitempty"`   // JSON Web Key containing the public key and MUST be present in NewAccount and RevokeCert requests (mutually exclusive with KID)
	KID   string `json:"kid,omitempty"`   // Key ID containing the account URL and MUST be present in all other requests (mutually exclusive with JWK)
}

// According to RFC 7517 - JSON Web Key (JWK)
// See https://www.rfc-editor.org/rfc/rfc7517#section-4
type JWK struct {
	Kty string `json:"kty,omitempty"` // identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC"
	N   string `json:"n,omitempty"`   // modulo
	E   string `json:"e,omitempty"`   // exponent
	Alg string `json:"alg,omitempty"` // identifies the algorithm intended for use with the key, such as RS256
}

// According to RFC 7515 - JSON Web Signature (JWS)
// See https://www.rfc-editor.org/rfc/rfc7515#section-3
func GenerateJWS(publicKey rsa.PublicKey, signingKey *rsa.PrivateKey, nonce string, targetURL string, payloadRaw interface{}) ([]byte, error) {
	// header
	jwk := JWK{
		Kty: keyType,
		N:   encodeBase64url(publicKey.N.Bytes()),
		E:   encodeBase64url(big.NewInt(int64(publicKey.E)).Bytes()),
	}
	h := JWSProtectedHeader{
		Alg:   algorithm,
		Nonce: nonce,
		URL:   targetURL,
		JWK:   jwk,
		// TODO refactor to work with other requests as well -> KID -> seperate methods for each message type
	}
	header, err := marshalAndEncodeSegment(h)
	if err != nil {
		log.WithError(err).Error("Failed to encode header.")
		return nil, err
	}

	// payload
	payload, err := marshalAndEncodeSegment(payloadRaw)
	if err != nil {
		log.WithError(err).Error("Failed to encode payload.")
		return nil, err
	}

	// signature
	signature, err := computeSignature(
		signingKey,
		[]byte(strings.Join([]string{header, payload}, ".")),
	)
	if err != nil {
		log.WithError(err).Error("Failed to compute signature.")
		return nil, err
	}

	// assemble JWS
	j := JWS{
		Header:    header,
		Payload:   payload,
		Signature: signature,
	}
	jws, err := marshallSegment(j)
	if err != nil {
		log.WithError(err).Error("Failed to marshall JWS.")
		return nil, err
	}

	return jws, nil
}

func marshalAndEncodeSegment(s interface{}) (string, error) {
	json, err := marshallSegment(s)
	if err != nil {
		return "", err
	}

	encoded := encodeBase64url(json)
	log.WithField("encoded segment", encoded).Debug("Encoded segment.")

	return encoded, nil
}

func marshallSegment(s interface{}) ([]byte, error) {
	l := log.WithFields(log.Fields{"segment": fmt.Sprintf("%+v", s)})

	json, err := json.Marshal(s)
	if err != nil {
		l.WithError(err).Error("Failed to marshall segment.")
		return nil, err
	}
	l.WithField("JSON segment", string(json)).Debug("Marshalled segment.")

	return json, nil
}

func computeSignature(signingKey *rsa.PrivateKey, p []byte) (string, error) {
	hasher := crypto.SHA256.New()
	hasher.Write(p)

	signBytes, err := signingKey.Sign(rand.Reader, hasher.Sum(nil), crypto.SHA256)
	if err != nil {
		log.WithError(err).Error("Failed to sign header and payload.")
		return "", err
	}

	signature := encodeBase64url(signBytes)
	log.WithField("Signature", signature).Debug("Computed signature.")

	return signature, nil
}

func encodeBase64url(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
