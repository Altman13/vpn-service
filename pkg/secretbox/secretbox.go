// Package secretbox шифрует секреты, которые сервис хранит вне памяти:
// приватные ключи устройств, которые нельзя держать в БД открытым текстом.
//
// Формат: "enc:v1:" + base64(nonce || AES-256-GCM(plaintext)).
// Значения без префикса считаются унаследованными и возвращаются как есть,
// чтобы старые записи продолжали работать после включения шифрования.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	prefix   = "enc:v1:"
	keySize  = 32
	nonceLen = 12
)

var (
	ErrInvalidKey       = errors.New("encryption key must be 32 bytes")
	ErrCiphertextBroken = errors.New("ciphertext is broken or was encrypted with another key")
)

// Box — шифр с ключом. Zero value непригоден: используйте New.
type Box struct {
	aead cipher.AEAD
}

// New создаёт шифр из 32-байтового ключа.
func New(key []byte) (*Box, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKey, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return &Box{aead: aead}, nil
}

// FromBase64 создаёт шифр из ключа в base64: так его удобно держать в env-переменной.
func FromBase64(encoded string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	return New(key)
}

// Seal шифрует значение и добавляет метку версии.
func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := b.aead.Seal(nil, nonce, []byte(plaintext), nil)

	payload := make([]byte, 0, nonceLen+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return prefix + base64.StdEncoding.EncodeToString(payload), nil
}

// Open расшифровывает значение. Незашифрованные значения возвращаются как есть.
func (b *Box) Open(value string) (string, error) {
	if !IsSealed(value) {
		return value, nil
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCiphertextBroken, err)
	}
	if len(payload) < nonceLen {
		return "", ErrCiphertextBroken
	}

	plaintext, err := b.aead.Open(nil, payload[:nonceLen], payload[nonceLen:], nil)
	if err != nil {
		return "", ErrCiphertextBroken
	}
	return string(plaintext), nil
}

// IsSealed сообщает, что значение зашифровано этим сервисом.
func IsSealed(value string) bool {
	return strings.HasPrefix(value, prefix)
}
