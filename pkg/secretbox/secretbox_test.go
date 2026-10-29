package secretbox

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()

	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(i)
	}
	box, err := New(key)
	if err != nil {
		t.Fatalf("создание шифра: %v", err)
	}
	return box
}

func TestSealOpenRoundTrip(t *testing.T) {
	box := newBox(t)

	const secret = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="

	sealed, err := box.Seal(secret)
	if err != nil {
		t.Fatalf("шифрование: %v", err)
	}
	if !IsSealed(sealed) {
		t.Fatalf("значение без метки версии: %q", sealed)
	}
	if strings.Contains(sealed, secret) {
		t.Fatal("открытый текст виден в шифротексте")
	}

	opened, err := box.Open(sealed)
	if err != nil {
		t.Fatalf("расшифровка: %v", err)
	}
	if opened != secret {
		t.Fatalf("получено %q, ожидалось %q", opened, secret)
	}
}

// Одинаковые секреты должны давать разные шифротексты: иначе по БД видно,
// у каких устройств совпадают ключи.
func TestSealUsesRandomNonce(t *testing.T) {
	box := newBox(t)

	first, err := box.Seal("same-secret")
	if err != nil {
		t.Fatalf("шифрование: %v", err)
	}
	second, err := box.Seal("same-secret")
	if err != nil {
		t.Fatalf("шифрование: %v", err)
	}
	if first == second {
		t.Fatal("шифротексты совпали — nonce не случайный")
	}
}

func TestOpenReturnsLegacyPlaintext(t *testing.T) {
	box := newBox(t)

	opened, err := box.Open("plain-key-without-prefix")
	if err != nil {
		t.Fatalf("расшифровка: %v", err)
	}
	if opened != "plain-key-without-prefix" {
		t.Fatalf("получено %q", opened)
	}
}

func TestOpenFailsWithAnotherKey(t *testing.T) {
	first := newBox(t)

	otherKey := make([]byte, keySize)
	for i := range otherKey {
		otherKey[i] = 0xFF
	}
	other, err := New(otherKey)
	if err != nil {
		t.Fatalf("создание второго шифра: %v", err)
	}

	sealed, err := first.Seal("secret")
	if err != nil {
		t.Fatalf("шифрование: %v", err)
	}

	if _, err := other.Open(sealed); !errors.Is(err, ErrCiphertextBroken) {
		t.Fatalf("ожидалась ErrCiphertextBroken, получено %v", err)
	}
}

func TestOpenDetectsTampering(t *testing.T) {
	box := newBox(t)

	sealed, err := box.Seal("secret")
	if err != nil {
		t.Fatalf("шифрование: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0x01 // портим последний байт шифротекста
	tampered := prefix + base64.StdEncoding.EncodeToString(raw)

	if _, err := box.Open(tampered); !errors.Is(err, ErrCiphertextBroken) {
		t.Fatalf("изменённый шифротекст принят: %v", err)
	}
}

func TestNewRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 64} {
		if _, err := New(make([]byte, size)); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("ключ длиной %d принят", size)
		}
	}
}

func TestFromBase64(t *testing.T) {
	key := make([]byte, keySize)
	encoded := base64.StdEncoding.EncodeToString(key)

	if _, err := FromBase64(encoded); err != nil {
		t.Fatalf("ключ из base64: %v", err)
	}
	if _, err := FromBase64("не-base64"); err == nil {
		t.Fatal("некорректный base64 принят")
	}
	if _, err := FromBase64(base64.StdEncoding.EncodeToString(make([]byte, 8))); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("короткий ключ принят")
	}
}
