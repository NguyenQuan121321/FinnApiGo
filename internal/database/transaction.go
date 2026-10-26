package database

import (
	"context"
	"gorm.io/gorm"
	"sync"
)

type operationKey struct{}
type asyncDeliveryKey struct{}

func WithAsyncDelivery(ctx context.Context) context.Context {
	return context.WithValue(ctx, asyncDeliveryKey{}, true)
}
func AsyncDelivery(ctx context.Context) bool { v, _ := ctx.Value(asyncDeliveryKey{}).(bool); return v }

// Operation binds all repositories in a service operation to the same SQL
// transaction. The error latch preserves compatibility with legacy void Record
// callers: admission failure can never be mistaken for successful completion.
type Operation struct {
	Tx         *gorm.DB
	mu         sync.Mutex
	failure    error
	admissions int
	successful bool
}

func (o *Operation) Admitted(success bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.admissions++
	o.successful = o.successful || success
}

// Only explicit denial/containment evidence may commit a denied operation.
// A partially prepared issuance (or factor success followed by denial) must
// roll back its SQL state and cannot leave a success event behind.
func (o *Operation) DenialMayCommit() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.admissions > 0 && !o.successful
}

func BindOperation(ctx context.Context, tx *gorm.DB) (context.Context, *Operation) {
	o := &Operation{Tx: tx}
	return context.WithValue(ctx, operationKey{}, o), o
}
func CurrentOperation(ctx context.Context) *Operation {
	o, _ := ctx.Value(operationKey{}).(*Operation)
	return o
}
func (o *Operation) Fail(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failure == nil {
		o.failure = err
	}
}
func (o *Operation) Failure() error { o.mu.Lock(); defer o.mu.Unlock(); return o.failure }
func FromContext(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	if o := CurrentOperation(ctx); o != nil {
		return o.Tx.WithContext(ctx)
	}
	return fallback.WithContext(ctx)
}
