package models

import (
	"time"
)

type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password_hash"`
	FullName  string    `json:"full_name" db:"full_name"`
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type Device struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	Name       string    `json:"name" db:"name"`
	Protocol   string    `json:"protocol" db:"protocol"` // wireguard, openvpn
	DeviceKey  string    `json:"-" db:"device_key"`
	PublicKey  string    `json:"public_key,omitempty" db:"public_key"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	Status     string    `json:"status" db:"status"` // active, revoked, expired
	LastActive time.Time `json:"last_active" db:"last_active"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
}

type Session struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	DeviceID  string    `json:"device_id" db:"device_id"`
	Token     string    `json:"-" db:"token"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
