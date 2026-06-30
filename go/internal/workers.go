package internal

import (
	"sync"
)

// PoolResult holds the result of a worker pool job at a given index.
type PoolResult[T any] struct {
	Idx int
	Val T
}

// RunWorkerPool dispatches fn across numWorkers goroutines for each item in jobs.
// Results preserve input ordering via index.
func RunWorkerPool[T, R any](jobs []T, fn func(T) R, numWorkers int) []R {
	if len(jobs) == 0 {
		return nil
	}
	if numWorkers <= 0 {
		numWorkers = 20
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	jobCh := make(chan int, len(jobs))
	resCh := make(chan PoolResult[R], len(jobs)) // Buffered to prevent deadlocks

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobCh {
				resCh <- PoolResult[R]{Idx: idx, Val: fn(jobs[idx])}
			}
		}()
	}

	// Push jobs concurrently to avoid blocking
	go func() {
		for i := range jobs {
			jobCh <- i
		}
		close(jobCh)
	}()

	// Drain goroutine strictly prevents Send on closed panic
	go func() {
		wg.Wait()
		close(resCh)
	}()

	results := make([]R, len(jobs))
	for r := range resCh {
		results[r.Idx] = r.Val
	}
	return results
}
