package ratelimit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeCounter struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
	calls  int
	ttls   map[string]time.Duration
}

func newFakeCounter() *fakeCounter {
	return &fakeCounter{counts: make(map[string]int64), ttls: make(map[string]time.Duration)}
}

func (c *fakeCounter) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls++
	if c.err != nil {
		return 0, c.err
	}
	c.counts[key]++
	c.ttls[key] = ttl
	return c.counts[key], nil
}

func TestMemoryLimiterAllowsUpToLimit(t *testing.T) {
	limiter := NewMemoryLimiter(3, time.Minute)
	ctx := context.Background()

	for attempt := 1; attempt <= 3; attempt++ {
		decision, err := limiter.Allow(ctx, "ip:1.2.3.4")
		if err != nil {
			t.Fatalf("попытка %d: %v", attempt, err)
		}
		if !decision.Allowed {
			t.Fatalf("попытка %d должна быть разрешена", attempt)
		}
	}

	decision, err := limiter.Allow(ctx, "ip:1.2.3.4")
	if err != nil {
		t.Fatalf("попытка 4: %v", err)
	}
	if decision.Allowed {
		t.Fatal("четвёртая попытка должна быть отклонена")
	}
	if decision.Remaining != 0 {
		t.Fatalf("remaining=%d, ожидался 0", decision.Remaining)
	}
	if decision.RetryAfter <= 0 || decision.RetryAfter > time.Minute {
		t.Fatalf("некорректный Retry-After: %v", decision.RetryAfter)
	}
}

func TestMemoryLimiterIsolatesKeys(t *testing.T) {
	limiter := NewMemoryLimiter(1, time.Minute)
	ctx := context.Background()

	if decision, _ := limiter.Allow(ctx, "ip:1.1.1.1"); !decision.Allowed {
		t.Fatal("первый клиент должен быть пропущен")
	}
	if decision, _ := limiter.Allow(ctx, "ip:1.1.1.1"); decision.Allowed {
		t.Fatal("повторный запрос должен быть отклонён")
	}
	if decision, _ := limiter.Allow(ctx, "ip:2.2.2.2"); !decision.Allowed {
		t.Fatal("второй клиент не должен страдать от лимита первого")
	}
}

func TestMemoryLimiterResetsAfterWindow(t *testing.T) {
	limiter := NewMemoryLimiter(1, time.Minute)
	current := time.Now()
	limiter.now = func() time.Time { return current }
	ctx := context.Background()

	if decision, _ := limiter.Allow(ctx, "key"); !decision.Allowed {
		t.Fatal("первый запрос должен быть пропущен")
	}
	if decision, _ := limiter.Allow(ctx, "key"); decision.Allowed {
		t.Fatal("второй запрос должен быть отклонён")
	}

	current = current.Add(2 * time.Minute)
	if decision, _ := limiter.Allow(ctx, "key"); !decision.Allowed {
		t.Fatal("после окна лимит должен сброситься")
	}
}

func TestCounterLimiterUsesSharedCounterAndWindowKey(t *testing.T) {
	counter := newFakeCounter()
	limiter := NewCounterLimiter(counter, 2, time.Minute)
	ctx := context.Background()

	if decision, _ := limiter.Allow(ctx, "login:ip"); !decision.Allowed {
		t.Fatal("первый запрос должен быть пропущен")
	}
	if decision, _ := limiter.Allow(ctx, "login:ip"); !decision.Allowed {
		t.Fatal("второй запрос должен быть пропущен")
	}

	decision, _ := limiter.Allow(ctx, "login:ip")
	if decision.Allowed {
		t.Fatal("третий запрос должен быть отклонён")
	}

	for key, ttl := range counter.ttls {
		if ttl != time.Minute {
			t.Fatalf("счётчик %s получил TTL %v, ожидалась минута", key, ttl)
		}
	}
	if len(counter.ttls) != 1 {
		t.Fatalf("счётчиков создано %d, ожидался 1 на текущее окно", len(counter.ttls))
	}
}

// При недоступном хранилище лимитер пропускает запрос, но сообщает об ошибке:
// так падение Redis не блокирует вход пользователей.
func TestCounterLimiterFailOpen(t *testing.T) {
	counter := newFakeCounter()
	counter.err = errors.New("redis is down")
	limiter := NewCounterLimiter(counter, 1, time.Minute)

	decision, err := limiter.Allow(context.Background(), "login:ip")
	if err == nil {
		t.Fatal("ожидалась ошибка хранилища")
	}
	if !decision.Allowed {
		t.Fatal("при ошибке хранилища запрос должен пропускаться")
	}
}

func TestLimiterWithZeroLimitAllowsEverything(t *testing.T) {
	limiter := NewMemoryLimiter(0, time.Minute)

	for i := 0; i < 5; i++ {
		if decision, _ := limiter.Allow(context.Background(), "key"); !decision.Allowed {
			t.Fatal("при limit=0 ограничение должно быть выключено")
		}
	}
}
