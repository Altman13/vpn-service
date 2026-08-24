package postgres

import (
	"context"
	"database/sql"
	"vpn-service/internal/storage/models"
)

func (db *DB) CreateDevice(ctx context.Context, device *models.Device) error {
	query := `
		INSERT INTO devices (id, user_id, name, protocol, device_key, ip_address, status, created_at, updated_at, last_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := db.ExecContext(ctx, query,
		device.ID, device.UserID, device.Name, device.Protocol,
		device.DeviceKey, device.IPAddress, device.Status,
		device.CreatedAt, device.UpdatedAt, device.LastActive,
	)
	return err
}

func (db *DB) GetDevice(ctx context.Context, id string) (*models.Device, error) {
	query := `SELECT id, user_id, name, protocol, device_key, ip_address, status, created_at, updated_at, last_active FROM devices WHERE id = $1`
	var device models.Device
	err := db.GetContext(ctx, &device, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &device, nil
}

func (db *DB) GetDevicesByUser(ctx context.Context, userID string) ([]models.Device, error) {
	query := `SELECT id, user_id, name, protocol, device_key, ip_address, status, created_at, updated_at, last_active FROM devices WHERE user_id = $1 ORDER BY created_at DESC`
	var devices []models.Device
	err := db.SelectContext(ctx, &devices, query, userID)
	return devices, err
}

func (db *DB) UpdateDeviceStatus(ctx context.Context, id, status string) error {
	query := `UPDATE devices SET status = $1, updated_at = NOW() WHERE id = $2`
	_, err := db.ExecContext(ctx, query, status, id)
	return err
}


