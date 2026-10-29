-- Серийный номер клиентского сертификата OpenVPN: нужен для отзыва через CRL.
-- +goose Up
ALTER TABLE devices ADD COLUMN IF NOT EXISTS cert_serial VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_devices_cert_serial ON devices(cert_serial);

-- +goose Down
DROP INDEX IF EXISTS idx_devices_cert_serial;
ALTER TABLE devices DROP COLUMN IF EXISTS cert_serial;
