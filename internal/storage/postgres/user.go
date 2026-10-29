package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"vpn-service/internal/storage/models"
)

// ErrDuplicateEmail — попытка создать пользователя с занятым email.
// Хендлер превращает её в 409, не разбирая текст ошибки Postgres.
var ErrDuplicateEmail = errors.New("email already registered")

// uniqueViolation — код нарушения уникальности в Postgres.
const uniqueViolation = "23505"

func (db *DB) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, full_name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := db.ExecContext(ctx, query,
		user.ID, user.Email, user.Password, user.FullName,
		user.Status, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		// Проверка «email занят» отдельным запросом оставляла окно гонки:
		// между SELECT и INSERT успевал вставиться другой пользователь.
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && string(pqErr.Code) == uniqueViolation {
			return ErrDuplicateEmail
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// GetUser возвращает пользователя или sql.ErrNoRows, если записи нет.
func (db *DB) GetUser(ctx context.Context, id string) (*models.User, error) {
	query := `SELECT id, email, password_hash, full_name, status, created_at, updated_at FROM users WHERE id = $1`
	var user models.User
	if err := db.GetContext(ctx, &user, query, id); err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail возвращает пользователя или sql.ErrNoRows.
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, password_hash, full_name, status, created_at, updated_at FROM users WHERE email = $1`
	var user models.User
	if err := db.GetContext(ctx, &user, query, email); err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserStatus возвращает статус пользователя или sql.ErrNoRows.
// Используется middleware: блокировка должна действовать сразу, а не после
// истечения токена.
func (db *DB) GetUserStatus(ctx context.Context, id string) (string, error) {
	var status string
	err := db.GetContext(ctx, &status, `SELECT status FROM users WHERE id = $1`, id)
	return status, err
}

// UpdateUser меняет отображаемое имя. Email здесь не меняется: смена адреса
// требует подтверждения владения, а это отдельный сценарий.
func (db *DB) UpdateUser(ctx context.Context, id, fullName string) error {
	query := `UPDATE users SET full_name = $1, updated_at = NOW() WHERE id = $2`
	result, err := db.ExecContext(ctx, query, fullName, id)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
