-- Уникальность выданных адресов: два устройства не должны получить один IP.
-- Индекс частичный — отозванное устройство адрес освобождает.
-- +goose Up
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_active
    ON devices (ip_address)
    WHERE status <> 'revoked' AND ip_address IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_devices_ip_active;
