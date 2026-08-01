// Signing the approved record.
//
// A lockfile answers "who approved this", and until it is signed the answer is
// "whoever could write the file". Version control and review close most of
// that, and not the case where an attacker already has commit rights or the
// pipeline pulls the lockfile from somewhere less careful than a repository.
//
// The signature is detached: it is a second file, so a lockfile stays readable
// and reviewable, and a repository that does not sign carries nothing extra.
package mcppin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// SignatureSchemaVersion versions the envelope.
const SignatureSchemaVersion = 1

const (
	signatureSchema    = "mcppin-lock-signature"
	signatureAlgorithm = "ed25519"
)

// Signature is the detached envelope. Everything in it except the signature
// itself is signed, so a signature cannot be lifted onto another envelope: the
// digest it vouches for, the key that made it and the moment it was made are
// bound together or not at all.
type Signature struct {
	Schema               string `json:"schema"`
	SchemaVersion        int    `json:"schema_version"`
	Algorithm            string `json:"algorithm"`
	LockDigest           string `json:"lock_digest"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	SignedAt             string `json:"signed_at"`
	Signature            string `json:"signature,omitempty"`
}

// LockDigest is the digest a signature vouches for: the canonical form of the
// lockfile as it is read, not of the bytes as they sit on disk. Re-indenting a
// lockfile does not break its signature; changing a digest, a name or an
// approved description does.
func LockDigest(lockfile []byte) (string, error) {
	value, err := DecodeJSON(lockfile)
	if err != nil {
		return "", fmt.Errorf("lockfile cannot be read: %w", err)
	}
	return Digest(value)
}

// Fingerprint names a public key by the SHA-256 of its SPKI DER form, which is
// what every other tool means by the fingerprint of a key.
func Fingerprint(key ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return digestAlgorithm + hex.EncodeToString(sum[:]), nil
}

// SignLock builds the envelope for a lockfile and signs it.
func SignLock(lockfile []byte, key ed25519.PrivateKey, at time.Time) (*Signature, error) {
	digest, err := LockDigest(lockfile)
	if err != nil {
		return nil, err
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("the key is not an Ed25519 key")
	}
	fingerprint, err := Fingerprint(public)
	if err != nil {
		return nil, err
	}

	signature := &Signature{
		Schema:               signatureSchema,
		SchemaVersion:        SignatureSchemaVersion,
		Algorithm:            signatureAlgorithm,
		LockDigest:           digest,
		PublicKeyFingerprint: fingerprint,
		SignedAt:             at.UTC().Format(time.RFC3339),
	}
	payload, err := signingPayload(*signature)
	if err != nil {
		return nil, err
	}
	signature.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return signature, nil
}

// CheckSignature reports which trusted key vouches for the lockfile.
//
// Everything is checked against the file in hand: an envelope for a different
// lockfile, an algorithm this build does not know, or a key nobody said to
// trust are each a refusal, because each of them ends with a signature that
// verifies and proves nothing.
func CheckSignature(lockfile []byte, signature *Signature, trusted []ed25519.PublicKey) (string, error) {
	if signature.Schema != signatureSchema {
		return "", fmt.Errorf("the envelope is %q, this build reads %q", signature.Schema, signatureSchema)
	}
	if signature.SchemaVersion != SignatureSchemaVersion {
		return "", fmt.Errorf("the envelope is version %d, this build reads version %d",
			signature.SchemaVersion, SignatureSchemaVersion)
	}
	if signature.Algorithm != signatureAlgorithm {
		return "", fmt.Errorf("the signature algorithm is %q, this build knows %q",
			signature.Algorithm, signatureAlgorithm)
	}
	raw, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil {
		return "", fmt.Errorf("the signature is not base64: %w", err)
	}

	digest, err := LockDigest(lockfile)
	if err != nil {
		return "", err
	}
	if digest != signature.LockDigest {
		return "", fmt.Errorf("the signature vouches for %s and this lockfile is %s",
			signature.LockDigest, digest)
	}

	payload, err := signingPayload(*signature)
	if err != nil {
		return "", err
	}
	for _, key := range trusted {
		fingerprint, err := Fingerprint(key)
		if err != nil {
			return "", err
		}
		if fingerprint != signature.PublicKeyFingerprint {
			continue
		}
		if !ed25519.Verify(key, payload, raw) {
			return "", fmt.Errorf("the signature does not verify against %s", fingerprint)
		}
		return fingerprint, nil
	}
	return "", fmt.Errorf("the signature was made by %s, which is not a key this run was told to trust",
		signature.PublicKeyFingerprint)
}

// signingPayload is the canonical form of the envelope without its signature.
func signingPayload(signature Signature) ([]byte, error) {
	signature.Signature = ""
	encoded, err := json.Marshal(signature)
	if err != nil {
		return nil, err
	}
	value, err := DecodeJSON(encoded)
	if err != nil {
		return nil, err
	}
	return Canonicalize(value)
}

// ReadSignature decodes an envelope.
func ReadSignature(r io.Reader) (*Signature, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	value, err := DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("signature cannot be read: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("signature must be a JSON object")
	}
	version, err := intField(object, "schema_version")
	if err != nil {
		return nil, err
	}
	signature := &Signature{SchemaVersion: version}
	for _, field := range []struct {
		key  string
		into *string
	}{
		{"schema", &signature.Schema},
		{"algorithm", &signature.Algorithm},
		{"lock_digest", &signature.LockDigest},
		{"public_key_fingerprint", &signature.PublicKeyFingerprint},
		{"signed_at", &signature.SignedAt},
		{"signature", &signature.Signature},
	} {
		text, ok := object[field.key].(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("the signature has no %s", field.key)
		}
		*field.into = text
	}
	return signature, nil
}

// WriteSignature emits an envelope.
func WriteSignature(w io.Writer, signature *Signature) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(signature)
}

// LoadSignature reads an envelope from a file.
func LoadSignature(path string) (*Signature, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	signature, err := ReadSignature(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return signature, nil
}

// SignaturePath is where the signature of a lockfile lives by default.
func SignaturePath(lockPath string) string { return lockPath + ".sig" }

// GenerateSigningKey returns a new Ed25519 pair.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePrivateKey renders a private key as PKCS#8 PEM, which is what openssl
// and every other tool here already reads.
func EncodePrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKey renders a public key as SPKI PEM.
func EncodePublicKey(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadPrivateKey reads a PKCS#8 PEM private key. The key is not decrypted,
// because this build has no way to ask for a passphrase that is better than
// the one your operating system or your secret store already has.
func LoadPrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found; expected a PKCS#8 PRIVATE KEY")
	}
	if block.Type == "OPENSSH PRIVATE KEY" {
		return nil, errors.New("this is an OpenSSH key; convert it with " +
			"ssh-keygen -p -m PKCS8 -f <key> or generate one with mcppin key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the private key cannot be read: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the private key is %T, and this build signs with Ed25519", parsed)
	}
	return key, nil
}

// LoadPublicKey reads an SPKI PEM public key.
func LoadPublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found; expected an SPKI PUBLIC KEY")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the public key cannot be read: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the public key is %T, and this build verifies Ed25519", parsed)
	}
	return key, nil
}
