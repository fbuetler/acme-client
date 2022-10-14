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
	Header    string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type JWSProtectedHeader struct {
	Alg   string `json:"alg,omitempty"`   // This field MUST NOT contain "none" or a Message Authentication Code (MAC) algorithm (e.g. one in which the algorithm registry description mentions MAC/HMAC)
	Nonce string `json:"nonce,omitempty"` // nonce
	URL   string `json:"url,omitempty"`   // URL to the account used
	JWK   *JWK   `json:"jwk,omitempty"`   // JSON Web Key containing the public key and MUST be present in NewAccount and RevokeCert requests (mutually exclusive with KID)
	KID   string `json:"kid,omitempty"`   // Key ID containing the account URL and MUST be present in all other requests (mutually exclusive with JWK)
}

// According to RFC 7517 - JSON Web Key (JWK)
// See https://www.rfc-editor.org/rfc/rfc7517#section-4
type JWK struct { // order matters!
	E   string `json:"e,omitempty"`   // exponent
	Kty string `json:"kty,omitempty"` // identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC"
	N   string `json:"n,omitempty"`   // modulo
	// Alg string `json:"alg,omitempty"` // identifies the algorithm intended for use with the key, such as RS256
}

type Signer struct {
	Signer    *rsa.PrivateKey
	PublicKey *rsa.PublicKey
	hash      crypto.Hash
	algoritm  string
}

func New(signer *rsa.PrivateKey) (*Signer, error) {
	var publicKey *rsa.PublicKey
	var hash crypto.Hash
	var alg string

	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		publicKey = pub
		alg = "RS256"
		hash = crypto.SHA256
	default:
		return nil, errors.New("unsupported key type")
	}

	return &Signer{
		Signer:    signer,
		PublicKey: publicKey,
		hash:      hash,
		algoritm:  alg,
	}, nil
}

// According to RFC 7515 - JSON Web Signature (JWS)
// See https://www.rfc-editor.org/rfc/rfc7515#section-3
func (jws *Signer) Encode(nonce, targetURL, kid string, payloadRaw interface{}) ([]byte, error) {
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

func (jws *Signer) encodeHeader(nonce, targetURL, kid string) (string, error) {
	h := JWSProtectedHeader{
		Alg:   jws.algoritm,
		Nonce: nonce,
		URL:   targetURL,
	}

	if kid == NoKeyID {
		h.JWK = &JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(jws.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(jws.PublicKey.E)).Bytes()),
		}
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

func (jws *Signer) computeSignature(p []byte) (string, error) {
	hasher := jws.hash.New()
	hasher.Write(p)

	signBytes, err := jws.Signer.Sign(rand.Reader, hasher.Sum(nil), jws.hash)
	if err != nil {
		log.WithError(err).Error("Failed to sign header and payload.")
		return "", err
	}

	signature := base64.RawURLEncoding.EncodeToString(signBytes)
	// log.Debug("Computed signature.")

	return signature, nil
}

func marshalAndEncodeSegment(s interface{}) (string, error) {
	if s == nil {
		return "", nil
	}

	json, err := marshallSegment(s)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(json)
	// log.Debug("Encoded segment.")

	return encoded, nil
}

func marshallSegment(s interface{}) ([]byte, error) {
	json, err := json.Marshal(s)
	if err != nil {
		log.WithFields(log.Fields{"segment": fmt.Sprintf("%+v", s)}).WithError(err).Error("Failed to marshall segment.")
		return nil, err
	}
	// log.Debug("Marshalled segment.")

	return json, nil
}

func ComputeKeyThumbprint(signer *rsa.PrivateKey, publicKey *rsa.PublicKey) (string, error) {
	jwk := JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	json, err := marshallSegment(jwk)
	if err != nil {
		return "", err
	}
	// log.WithField("ordered JSON", string(json)).Debug("Marshalled account key.")

	hasher := crypto.SHA256.New()
	hasher.Write(json)
	hash := hasher.Sum(nil)
	// log.Debug("Hashed marshalled account key.")

	encoded := base64.RawURLEncoding.EncodeToString(hash)
	// log.Debug("Encoded hashed marshalled account key.")

	return encoded, nil
}
