package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	NoKeyID = ""
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

type jws struct {
	signer   crypto.Signer
	hash     crypto.Hash
	algoritm string
}

func New(signer crypto.Signer) (*jws, error) {
	var hash crypto.Hash
	var alg string

	switch signer.Public().(type) {
	case *rsa.PublicKey:
		alg = "RS256"
		hash = crypto.SHA256
	default:
		return nil, errors.New("unsupported key type")
	}

	return &jws{
		signer:   signer,
		hash:     hash,
		algoritm: alg,
	}, nil
}

// According to RFC 7515 - JSON Web Signature (JWS)
// See https://www.rfc-editor.org/rfc/rfc7515#section-3
func (jws *jws) Encode(nonce, targetURL, kid string, payloadRaw interface{}) ([]byte, error) {
	// header
	header, err := jws.encodeHeader(nonce, targetURL, kid)
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
	signature, err := jws.computeSignature(
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
	jwsJSON, err := marshallSegment(j)
	if err != nil {
		log.WithError(err).Error("Failed to marshall JWS.")
		return nil, err
	}

	return jwsJSON, nil
}

func (jws *jws) encodeHeader(nonce, targetURL, kid string) (string, error) {
	h := JWSProtectedHeader{
		Alg:   jws.algoritm,
		Nonce: nonce,
		URL:   targetURL,
	}

	if kid == NoKeyID {
		var jwk JWK
		switch pub := jws.signer.Public().(type) {
		case *rsa.PublicKey:
			jwk = JWK{
				Kty: "RSA",
				N:   encodeBase64url(pub.N.Bytes()),
				E:   encodeBase64url(big.NewInt(int64(pub.E)).Bytes()),
			}
		default:
			return "", errors.New("unsupported key type")
		}

		h.JWK = jwk
	} else {
		h.KID = kid
	}

	header, err := marshalAndEncodeSegment(h)
	if err != nil {
		log.WithError(err).Error("Failed to encode header.")
		return "", err
	}

	return header, nil
}

func (jws *jws) computeSignature(p []byte) (string, error) {
	hasher := jws.hash.New()
	hasher.Write(p)

	signBytes, err := jws.signer.Sign(rand.Reader, hasher.Sum(nil), jws.hash)
	if err != nil {
		log.WithError(err).Error("Failed to sign header and payload.")
		return "", err
	}

	signature := encodeBase64url(signBytes)
	log.WithField("Signature", signature).Debug("Computed signature.")

	return signature, nil
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
	json, err := json.Marshal(s)
	if err != nil {
		log.WithFields(log.Fields{"segment": fmt.Sprintf("%+v", s)}).WithError(err).Error("Failed to marshall segment.")
		return nil, err
	}
	log.WithField("JSON segment", string(json)).Debug("Marshalled segment.")

	return json, nil
}

func encodeBase64url(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
