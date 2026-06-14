// Package pool is an in-memory, content-addressed PoolPort: served canonical span bytes
// are stored under a sha256 cursor so pruned spans are re-openable with zero re-query, and
// so the receipt can prove which spans touched the model. (A persistent on-disk pool is a
// later adapter; this is the pure-Go reference + test impl.)
package pool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/akhilesharora/herkos/internal/core"
	"github.com/akhilesharora/herkos/internal/ports"
)

// Pool is a concurrency-safe in-memory span pool.
type Pool struct {
	mu sync.RWMutex
	m  map[core.Cursor][]byte
}

// New returns an empty pool.
func New() *Pool { return &Pool{m: make(map[core.Cursor][]byte)} }

// Put stores canonical bytes under their content-addressed cursor.
func (p *Pool) Put(_ context.Context, _ core.Span, canon []byte) (core.Cursor, error) {
	h := sha256.Sum256(canon)
	c := core.Cursor(hex.EncodeToString(h[:]))
	p.mu.Lock()
	p.m[c] = append([]byte(nil), canon...)
	p.mu.Unlock()
	return c, nil
}

// Open returns a copy of the bytes for a cursor, or an error if absent.
func (p *Pool) Open(_ context.Context, c core.Cursor) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, ok := p.m[c]
	if !ok {
		return nil, errors.New("mempool: cursor not found")
	}
	return append([]byte(nil), b...), nil
}

var _ ports.PoolPort = (*Pool)(nil)
