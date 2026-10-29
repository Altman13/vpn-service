package vpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile  = "ca.crt"
	caKeyFile   = "ca.key"
	crlFile     = "crl.pem"
	revokedFile = "revoked.json"

	defaultClientCertTTL = 365 * 24 * time.Hour
	caValidity           = 10 * 365 * 24 * time.Hour
	// CRL живёт неделю, а обновляется за двое суток до истечения. Если сервис
	// неделями не отзывает сертификаты, CRL на диске всё равно остаётся
	// валидной для crl-verify.
	crlValidity         = 7 * 24 * time.Hour
	crlRefreshThreshold = 2 * 24 * time.Hour
	serialBits          = 128
)

// PKI — собственный удостоверяющий центр сервиса.
//
// CA создаётся при первом запуске и переиспользуется: клиентские сертификаты
// должны быть подписаны одним и тем же ключом, иначе ранее выданные конфиги
// перестанут проверяться сервером. Отозванные сертификаты попадают в CRL,
// который сервер OpenVPN проверяет директивой crl-verify.
type PKI struct {
	dir    string
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	clock  func() time.Time

	mu      sync.Mutex
	revoked map[string]time.Time

	// crlNextUpdate — момент, до которого выпущенная CRL считается валидной.
	crlNextUpdate time.Time
}

// LoadOrCreatePKI открывает CA из каталога или создаёт новый.
func LoadOrCreatePKI(dir string) (*PKI, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("pki directory is not configured")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create pki directory: %w", err)
	}

	p := &PKI{
		dir:     dir,
		clock:   time.Now,
		revoked: make(map[string]time.Time),
	}

	if err := p.loadOrCreateCA(); err != nil {
		return nil, err
	}
	if err := p.loadRevoked(); err != nil {
		return nil, err
	}
	// CRL пишется сразу: сервер OpenVPN не должен зависеть от того,
	// было ли уже кого-то отзывать.
	if err := p.writeCRL(); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *PKI) loadOrCreateCA() error {
	certPath := filepath.Join(p.dir, caCertFile)
	keyPath := filepath.Join(p.dir, caKeyFile)

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	switch {
	case certExists && keyExists:
		return p.loadCA(certPath, keyPath)
	case certExists != keyExists:
		return fmt.Errorf("incomplete CA in %s: %s and %s must exist together", p.dir, caCertFile, caKeyFile)
	default:
		return p.createCA(certPath, keyPath)
	}
}

func (p *PKI) loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("CA certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("CA key is not valid PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	p.caCert = cert
	p.caKey = key
	p.caPEM = certPEM
	return nil
}

func (p *PKI) createCA(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	now := p.clock()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "vpn-service CA",
			Organization: []string{"vpn-service"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	// x509.CreateRevocationList отказывается подписывать CRL, если у CA нет
	// Subject Key Identifier, поэтому его надо выставить явно.
	subjectKeyID, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return err
	}
	template.SubjectKeyId = subjectKeyID

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Дальше используется разобранный сертификат, а не шаблон: у шаблона не
	// заполнены PublicKeyAlgorithm/SignatureAlgorithm, и проверка подписи
	// (CheckSignatureFrom) на нём падает с «algorithm unimplemented».
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse generated CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	// Ключ CA — самый чувствительный файл: только владельцу процесса.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	p.caCert = parsed
	p.caKey = key
	p.caPEM = certPEM
	return nil
}

// CAPEM возвращает сертификат CA в PEM: он подставляется в клиентский конфиг.
func (p *PKI) CAPEM() []byte {
	return p.caPEM
}

// IssueClient выпускает клиентский сертификат и возвращает его вместе с
// приватным ключом и серийным номером (серийный номер нужен для отзыва).
func (p *PKI) IssueClient(commonName string, ttl time.Duration) (certPEM, keyPEM []byte, serial string, err error) {
	if err := validateCommonName(commonName); err != nil {
		return nil, nil, "", err
	}
	if ttl <= 0 {
		ttl = defaultClientCertTTL
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generate client key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, nil, "", err
	}

	now := p.clock()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"vpn-service"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("sign client certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal client key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, serialNumber.Text(16), nil
}

// Revoke заносит серийный номер в CRL. Повторный отзыв идемпотентен.
func (p *PKI) Revoke(serial string) error {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return nil
	}
	if _, ok := new(big.Int).SetString(serial, 16); !ok {
		return fmt.Errorf("invalid certificate serial %q", serial)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, already := p.revoked[serial]; already {
		return nil
	}

	p.revoked[serial] = p.clock().UTC()
	if err := p.saveRevoked(); err != nil {
		return err
	}
	return p.writeCRL()
}

func (p *PKI) loadRevoked() error {
	data, err := os.ReadFile(filepath.Join(p.dir, revokedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read revoked list: %w", err)
	}

	var stored map[string]time.Time
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse revoked list: %w", err)
	}
	for serial, at := range stored {
		p.revoked[serial] = at
	}
	return nil
}

func (p *PKI) saveRevoked() error {
	data, err := json.MarshalIndent(p.revoked, "", "  ")
	if err != nil {
		return fmt.Errorf("encode revoked list: %w", err)
	}
	if err := os.WriteFile(filepath.Join(p.dir, revokedFile), data, 0o600); err != nil {
		return fmt.Errorf("write revoked list: %w", err)
	}
	return nil
}

// writeCRL пересобирает и подписывает CRL. Вызывается под p.mu.
func (p *PKI) writeCRL() error {
	entries := make([]x509.RevocationListEntry, 0, len(p.revoked))
	for serial, revokedAt := range p.revoked {
		number, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   number,
			RevocationTime: revokedAt,
		})
	}

	now := p.clock()
	template := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(crlValidity),
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, p.caCert, p.caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}

	path := filepath.Join(p.dir, crlFile)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("write CRL: %w", err)
	}

	p.crlNextUpdate = template.NextUpdate
	return nil
}

// EnsureFreshCRL пересобирает CRL, если до истечения осталось меньше
// crlRefreshThreshold. Вызывается при выдаче конфига и отзыве: сервер OpenVPN
// отвергает клиентов, если его CRL просрочена, а обновлять её по таймеру
// пришлось бы отдельной горутиной с собственным жизненным циклом.
func (p *PKI) EnsureFreshCRL() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.clock().Add(crlRefreshThreshold).Before(p.crlNextUpdate) {
		return nil
	}
	return p.writeCRL()
}

// CRLNextUpdate возвращает срок действия текущей CRL.
func (p *PKI) CRLNextUpdate() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.crlNextUpdate
}

// CRLPath возвращает путь к файлу CRL для директивы crl-verify.
func (p *PKI) CRLPath() string {
	return filepath.Join(p.dir, crlFile)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}

// validateCommonName не даёт подставить в конфиг разметку PEM-блоков.
func validateCommonName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("common name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("common name is too long: %d bytes", len(name))
	}
	if strings.ContainsAny(name, "<>\r\n") {
		return fmt.Errorf("common name contains forbidden characters")
	}
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// subjectKeyID считает идентификатор ключа по RFC 5280 (метод 1): SHA-1 от
// DER-представления открытого ключа. SHA-1 здесь не про криптостойкость,
// а про совместимость с тем, как идентификатор формирует OpenSSL.
func subjectKeyID(publicKey *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CA public key: %w", err)
	}
	sum := sha1.Sum(der)
	return sum[:], nil
}
