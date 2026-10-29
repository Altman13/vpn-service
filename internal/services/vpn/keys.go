package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const wireGuardKeySize = 32

// generateWireGuardKeyPair создаёт пару ключей Curve25519 в том же виде,
// в каком их ожидает wg/wg-quick: 32 байта, стандартный base64 с padding
// (44 символа). Произвольные байты в base64.URLEncoding, которые
// генерировались раньше, WireGuard отвергает.
func generateWireGuardKeyPair() (privateKey, publicKey string, err error) {
	private := make([]byte, wireGuardKeySize)
	if _, err := rand.Read(private); err != nil {
		return "", "", fmt.Errorf("generate wireguard private key: %w", err)
	}

	// Клэмпинг X25519: без него ключ не является корректным скаляром
	// и WireGuard откажется его импортировать.
	private[0] &= 248
	private[31] = (private[31] & 127) | 64

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive wireguard public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public), nil
}

// publicKeyFromPrivate повторно выводит публичный ключ из приватного.
// Нужен при выдаче конфига: в БД хранится только приватный ключ устройства.
func publicKeyFromPrivate(privateKey string) (string, error) {
	private, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(private) != wireGuardKeySize {
		return "", fmt.Errorf("invalid private key length: %d", len(private))
	}

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(public), nil
}
