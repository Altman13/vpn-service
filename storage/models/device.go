package models

import "time"

type Device struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	Name       string    `json:"name" db:"name"`
	Protocol   string    `json:"protocol" db:"protocol"`
	DeviceKey  string    `json:"-" db:"device_key"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	Status     string    `json:"status" db:"status"`
	LastActive time.Time `json:"last_active" db:"last_active"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}
