package vpn

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func decodeKey(t *testing.T, value string) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("ключ не декодируется стандартным base64: %v", err)
	}
	return raw
}

// Регрессия: раньше ключ кодировался base64.URLEncoding и был произвольными
// байтами. wg такой конфиг не принимает.
func TestGenerateWireGuardKeyPairProducesValidKeys(t *testing.T) {
	private, public, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("генерация ключей: %v", err)
	}

	privateRaw := decodeKey(t, private)
	publicRaw := decodeKey(t, public)

	if len(privateRaw) != wireGuardKeySize {
		t.Fatalf("длина приватного ключа %d, ожидалась %d", len(privateRaw), wireGuardKeySize)
	}
	if len(publicRaw) != wireGuardKeySize {
		t.Fatalf("длина публичного ключа %d, ожидалась %d", len(publicRaw), wireGuardKeySize)
	}
	// wg ожидает ровно 44 символа: 32 байта в base64 с padding.
	if len(private) != 44 || len(public) != 44 {
		t.Fatalf("длина base64-ключа %d/%d, ожидалось 44/44", len(private), len(public))
	}
	// '-' и '_' допустимы только в URL-safe варианте, который WireGuard не понимает.
	if containsAny(private+public, "-_") {
		t.Fatalf("ключи содержат URL-safe символы: %s %s", private, public)
	}
}

func TestGenerateWireGuardKeyPairIsClamped(t *testing.T) {
	private, _, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("генерация ключей: %v", err)
	}
	raw := decodeKey(t, private)

	if raw[0]&7 != 0 {
		t.Fatalf("младшие 3 бита первого байта не обнулены: %08b", raw[0])
	}
	if raw[31]&128 != 0 {
		t.Fatalf("старший бит последнего байта не обнулён: %08b", raw[31])
	}
	if raw[31]&64 != 64 {
		t.Fatalf("второй по старшинству бит не установлен: %08b", raw[31])
	}
}

func TestGenerateWireGuardKeyPairIsUnique(t *testing.T) {
	firstPrivate, firstPublic, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("генерация ключей: %v", err)
	}
	secondPrivate, secondPublic, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("генерация ключей: %v", err)
	}

	if firstPrivate == secondPrivate || firstPublic == secondPublic {
		t.Fatal("две пары ключей совпали — источник случайности сломан")
	}
}

// Публичный ключ, выведенный повторно, должен совпадать с сохранённым:
// именно он уходит в wg set при отзыве устройства.
func TestPublicKeyFromPrivateMatchesGeneratedPair(t *testing.T) {
	private, public, err := generateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("генерация ключей: %v", err)
	}

	derived, err := publicKeyFromPrivate(private)
	if err != nil {
		t.Fatalf("вывод публичного ключа: %v", err)
	}
	if derived != public {
		t.Fatalf("публичный ключ не совпал: получен %s, ожидался %s", derived, public)
	}

	expected, err := curve25519.X25519(decodeKey(t, private), curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	if base64.StdEncoding.EncodeToString(expected) != public {
		t.Fatal("публичный ключ не соответствует curve25519(Basepoint, private)")
	}
}

func TestPublicKeyFromPrivateRejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"не base64":     "not a key",
		"мало байт":     base64.StdEncoding.EncodeToString([]byte("short")),
		"пустая строка": "",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := publicKeyFromPrivate(value); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

func containsAny(haystack, needles string) bool {
	for _, needle := range needles {
		for _, char := range haystack {
			if char == needle {
				return true
			}
		}
	}
	return false
}
