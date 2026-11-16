package main

import (
	"context"
	"sync"
	"time"
)

// Прогресс проверки узлов: check.go не отдаёт промежуточный счётчик, поэтому
// здесь та же схема (8 воркеров, checkNode), но с колбэком на каждый узел.

func checkAllProgress(ctx context.Context, nodes []*Node, done func()) []checkResult {
	res := make([]checkResult, len(nodes))
	sem := make(chan struct{}, checkWorkers)
	var wg sync.WaitGroup
	notify := func() {
		if done != nil {
			done()
		}
	}
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n *Node) {
			defer wg.Done()
			switch {
			case n.Unsupported != "":
				res[i] = checkResult{status: "unsupported", err: n.Unsupported}
				notify()
			case n.Quic, n.AWG != "":
				// QUIC проверяется отдельно, в doCheck (временное ядро + SOCKS).
			default:
				sem <- struct{}{}
				res[i] = checkNode(ctx, n)
				<-sem
				notify()
			}
		}(i, n)
	}
	wg.Wait()
	return res
}

// beginProgress сбрасывает счётчик перед проверкой.
func (a *App) beginProgress(total int, phase string) {
	a.mu.Lock()
	a.progress = checkProgress{Checked: 0, Total: total, StartedAt: time.Now().Unix(), Phase: phase}
	a.mu.Unlock()
}

// bumpProgress отмечает один проверенный узел.
func (a *App) bumpProgress() {
	a.mu.Lock()
	if a.progress.Checked < a.progress.Total {
		a.progress.Checked++
	}
	a.mu.Unlock()
}

