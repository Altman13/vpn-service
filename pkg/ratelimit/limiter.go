// Package ratelimit реализует ограничение частоты запросов.
//
// Лимитер работает в двух вариантах: в памяти процесса (для одного инстанса
// и тестов) и поверх счётчика с TTL (Redis) — тогда лимит общий для всех
// реплик. Обе реализации используют одну и ту же модель: фиксированное окно.
package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Decision — результат проверки. Значения предназначены для заголовков
// ответа, поэтому заполняются и при отказе.
type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
}

// Limiter отвечает, можно ли выполнить запрос с данным ключом.
// Ошибка означает, что хранилище счётчиков недоступно: вызывающий код
// решает сам, пропускать запрос или нет.
type Limiter interface {
	Allow(ctx context.Context, key string) (Decision, error)
}

// Counter — хранилище счётчиков с TTL. Реализация Increment должна
// увеличивать значение и, если ключ создан впервые, выставлять TTL.
type Counter interface {
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
}

// CounterLimiter — фиксированное окно поверх общего счётчика.
// Ключ окна входит в имя счётчика, поэтому окна не «переезжают»
// и не требуют синхронизации между репликами.
type CounterLimiter struct {
	counter Counter
	limit   int
	window  time.Duration
}

func NewCounterLimiter(counter Counter, limit int, window time.Duration) *CounterLimiter {
	return &CounterLimiter{counter: counter, limit: limit, window: window}
}

func (l *CounterLimiter) Allow(ctx context.Context, key string) (Decision, error) {
	if l.limit <= 0 || l.window <= 0 {
		return Decision{Allowed: true, Limit: l.limit, Remaining: l.limit}, nil
	}

	now := time.Now()
	windowKey := fmt.Sprintf("%s:%d", key, now.Truncate(l.window).Unix())

	count, err := l.counter.Increment(ctx, windowKey, l.window)
	if err != nil {
		return Decision{Allowed: true, Limit: l.limit, Remaining: l.limit}, err
	}

	return decisionFor(int(count), l.limit, l.window, now), nil
}

// MemoryLimiter хранит счётчики в памяти процесса. Подходит для одного
// инстанса: у каждой реплики будет свой счётчик.
type MemoryLimiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	entries map[string]*memoryEntry
	now     func() time.Time
	maxKeys int
}

type memoryEntry struct {
	count   int
	resetAt time.Time
}

func NewMemoryLimiter(limit int, window time.Duration) *MemoryLimiter {
	return &MemoryLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]*memoryEntry),
		now:     time.Now,
		maxKeys: 10000,
	}
}

func (l *MemoryLimiter) Allow(_ context.Context, key string) (Decision, error) {
	if l.limit <= 0 || l.window <= 0 {
		return Decision{Allowed: true, Limit: l.limit, Remaining: l.limit}, nil
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Защита от неограниченного роста: ключи с истёкшим окном удаляются,
	// когда таблица превышает порог.
	if len(l.entries) > l.maxKeys {
		l.sweep(now)
	}

	entry, ok := l.entries[key]
	if !ok || !now.Before(entry.resetAt) {
		entry = &memoryEntry{resetAt: now.Add(l.window)}
		l.entries[key] = entry
	}
	entry.count++

	return decisionFor(entry.count, l.limit, l.window, now), nil
}

func (l *MemoryLimiter) sweep(now time.Time) {
	for key, entry := range l.entries {
		if !now.Before(entry.resetAt) {
			delete(l.entries, key)
		}
	}
}

func decisionFor(count, limit int, window time.Duration, now time.Time) Decision {
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	if count > limit {
		// До конца текущего окна запросы отклоняются.
		retryAfter := window - time.Duration(now.UnixNano()%int64(window))
		return Decision{Allowed: false, Limit: limit, Remaining: 0, RetryAfter: retryAfter}
	}

	return Decision{Allowed: true, Limit: limit, Remaining: remaining}
}
