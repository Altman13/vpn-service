package postgres

import (
	"context"
	"errors"
	"fmt"

	"vpn-service/internal/storage/models"
)

// COALESCE нужен для строк, созданных до появления public_key и cert_serial:
// там NULL, а скан в string NULL не переносит.
const deviceColumns = `id, user_id, name, protocol, device_key, COALESCE(public_key, '') AS public_key, COALESCE(cert_serial, '') AS cert_serial, ip_address, status, created_at, updated_at, last_active`

// ipAllocationLockKey — ключ advisory-блокировки выдачи адресов.
// Значение произвольное, важно лишь постоянство между репликами.
const ipAllocationLockKey int64 = 5772140411

const insertDeviceQuery = `
	INSERT INTO devices (id, user_id, name, protocol, device_key, public_key, ip_address, status, created_at, updated_at, last_active)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
`

// CreateDeviceWithAddress выделяет устройству свободный адрес и вставляет его
// в одной транзакции под advisory-блокировкой.
//
// Без блокировки два параллельных запроса читают один и тот же список занятых
// адресов, выбирают одинаковый свободный, и один из них падает на уникальном
// индексе. Блокировка сериализует только выбор адреса, а не всю запись.
func (db *DB) CreateDeviceWithAddress(
	ctx context.Context,
	device *models.Device,
	allocate func(used []string) (string, error),
) error {
	if allocate == nil {
		return errors.New("allocate callback is required")
	}

	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback после Commit возвращает ErrTxDone и ничего не меняет.
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, ipAllocationLockKey); err != nil {
		return fmt.Errorf("acquire address lock: %w", err)
	}

	var used []string
	const usedQuery = `SELECT ip_address FROM devices WHERE status <> 'revoked' AND ip_address IS NOT NULL AND ip_address <> ''`
	if err := tx.SelectContext(ctx, &used, usedQuery); err != nil {
		return fmt.Errorf("list allocated addresses: %w", err)
	}

	address, err := allocate(used)
	if err != nil {
		return err
	}
	device.IPAddress = address

	if _, err := tx.ExecContext(ctx, insertDeviceQuery,
		device.ID, device.UserID, device.Name, device.Protocol,
		device.DeviceKey, device.PublicKey, device.IPAddress,
		device.Status, device.CreatedAt, device.UpdatedAt, device.LastActive,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit device: %w", err)
	}
	return nil
}

// GetDevice возвращает устройство по идентификатору.
// Если записи нет, возвращается sql.ErrNoRows — вызывающий код обязан это
// обработать, а не разыменовывать nil.
func (db *DB) GetDevice(ctx context.Context, id string) (*models.Device, error) {
	query := `SELECT ` + deviceColumns + ` FROM devices WHERE id = $1`
	var device models.Device
	if err := db.GetContext(ctx, &device, query, id); err != nil {
		return nil, err
	}
	return &device, nil
}

// GetDeviceForUser возвращает устройство только если оно принадлежит userID.
// Фильтр по владельцу находится в SQL, поэтому IDOR невозможен даже при
// угаданном идентификаторе устройства.
func (db *DB) GetDeviceForUser(ctx context.Context, id, userID string) (*models.Device, error) {
	query := `SELECT ` + deviceColumns + ` FROM devices WHERE id = $1 AND user_id = $2`
	var device models.Device
	if err := db.GetContext(ctx, &device, query, id, userID); err != nil {
		return nil, err
	}
	return &device, nil
}

func (db *DB) GetDevicesByUser(ctx context.Context, userID string) ([]models.Device, error) {
	query := `SELECT ` + deviceColumns + ` FROM devices WHERE user_id = $1 ORDER BY created_at DESC`
	var devices []models.Device
	err := db.SelectContext(ctx, &devices, query, userID)
	return devices, err
}

func (db *DB) UpdateDeviceStatus(ctx context.Context, id, status string) error {
	query := `UPDATE devices SET status = $1, updated_at = NOW() WHERE id = $2`
	_, err := db.ExecContext(ctx, query, status, id)
	return err
}

// SetDeviceCertSerial сохраняет серийный номер сертификата OpenVPN.
func (db *DB) SetDeviceCertSerial(ctx context.Context, id, serial string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE devices SET cert_serial = $1, updated_at = NOW() WHERE id = $2`, serial, id)
	return err
}

// SetDeviceKey сохраняет перешифрованный приватный ключ устройства.
func (db *DB) SetDeviceKey(ctx context.Context, id, key string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE devices SET device_key = $1, updated_at = NOW() WHERE id = $2`, key, id)
	return err
}

// DeleteDevice используется для компенсации, когда запись в БД уже создана,
// а настройка пира/клиента завершилась ошибкой.
func (db *DB) DeleteDevice(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM devices WHERE id = $1`, id)
	return err
}
