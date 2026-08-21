package postgres

import (
	"context"
	"database/sql"
	"vpn-service/internal/storage/models"
)

func (db *DB) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, full_name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := db.ExecContext(ctx, query,
		user.ID, user.Email, user.Password, user.FullName,
		user.Status, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (db *DB) GetUser(ctx context.Context, id string) (*models.User, error) {
	query := `SELECT id, email, password_hash, full_name, status, created_at, updated_at FROM users WHERE id = $1`
	var user models.User
	err := db.GetContext(ctx, &user, query, id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, password_hash, full_name, status, created_at, updated_at FROM users WHERE email = $1`
	var user models.User
	err := db.GetContext(ctx, &user, query, email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *DB) UpdateUser(ctx context.Context, id, fullName string) error {
	query := `UPDATE users SET full_name = $1, updated_at = NOW() WHERE id = $2`
	_, err := db.ExecContext(ctx, query, fullName, id)
	return err
}
