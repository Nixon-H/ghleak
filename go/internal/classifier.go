package internal

import (
	"log"
	"regexp"
	"strings"
	"sync"
)

var tokenPattern = regexp.MustCompile(`[a-z0-9_.&!#$%]+`)

// CommitClassifier is the regex-first, AI-fallback classifier.
type CommitClassifier struct {
	llm    LLMBackend
	cache  map[string]Classification
	mu     sync.RWMutex
	stats  map[string]int
	hasLLM bool
}

// NewCommitClassifier creates a classifier with optional LLM fallback.
func NewCommitClassifier(llm LLMBackend) *CommitClassifier {
	return &CommitClassifier{
		llm:    llm,
		cache:  make(map[string]Classification),
		stats:  map[string]int{"cache_hit": 0, "patterns": 0, "regex_tier1": 0, "regex_tier2": 0, "llm": 0},
		hasLLM: llm != nil,
	}
}

// Classify a single commit message.
func (c *CommitClassifier) Classify(msg string) Classification {
	if msg == "" || strings.TrimSpace(msg) == "" {
		return Clean
	}

	key := strings.ToLower(strings.TrimSpace(msg))

	c.mu.RLock()
	if result, ok := c.cache[key]; ok {
		c.mu.RUnlock()
		c.stats["cache_hit"]++
		return result
	}
	c.mu.RUnlock()

	result := c.classifyCore(key)
	c.mu.Lock()
	c.cache[key] = result
	c.mu.Unlock()
	return result
}

// classifyCore runs regex tiers, then optional LLM fallback.
func (c *CommitClassifier) classifyCore(key string) Classification {
	// Tier 1: Compiled regex patterns
	for _, pat := range SecretRemovalPatterns {
		if pat.MatchString(key) {
			c.stats["patterns"]++
			return Suspicious
		}
	}
	for _, pat := range GitCredSweepPatterns {
		if pat.MatchString(key) {
			c.stats["patterns"]++
			return Suspicious
		}
	}

	// Tier 2: Word-list analysis
	words := tokenize(key)
	hasHighVerb := false
	hasHighNoun := false
	hasBroadVerb := false
	hasBroadNoun := false

	for w := range words {
		if HighConfidenceActionVerbs[w] {
			hasHighVerb = true
		}
		if HighConfidenceObjectNouns[w] {
			hasHighNoun = true
		}
		if BroadActionVerbs[w] {
			hasBroadVerb = true
		}
		if BroadObjectNouns[w] {
			hasBroadNoun = true
		}
	}

	if hasHighVerb && hasHighNoun {
		c.stats["regex_tier1"]++
		return Suspicious
	}
	if hasBroadVerb && hasBroadNoun {
		c.stats["regex_tier2"]++
		return Suspicious
	}

	// Tier 3: LLM fallback
	if c.hasLLM {
		result, err := c.llm.Classify(key)
		if err != nil {
			log.Printf("LLM classify error: %v", err)
			return Ambiguous
		}
		c.stats["llm"]++
		return result
	}

	return Clean
}

// Stats returns a copy of the internal counters.
func (c *CommitClassifier) Stats() map[string]int {
	out := make(map[string]int)
	for k, v := range c.stats {
		out[k] = v
	}
	return out
}

// ── BatchClassifier ────────────────────────────────────────────────

// BatchClassifier extends CommitClassifier with batched LLM calls.
type BatchClassifier struct {
	*CommitClassifier
}

// NewBatchClassifier creates a batch-optimized classifier.
func NewBatchClassifier(llm LLMBackend) *BatchClassifier {
	return &BatchClassifier{CommitClassifier: NewCommitClassifier(llm)}
}

// ClassifyBatch processes multiple messages, sending all ambiguous ones to the LLM in one shot.
func (b *BatchClassifier) ClassifyBatch(messages []string) []Classification {
	results := make([]Classification, len(messages))
	type pending struct {
		idx int
		msg string
	}
	var ambiguous []pending

	for i, msg := range messages {
		if msg == "" || strings.TrimSpace(msg) == "" {
			results[i] = Clean
			continue
		}

		key := strings.ToLower(strings.TrimSpace(msg))

		b.mu.RLock()
		if result, ok := b.cache[key]; ok {
			b.mu.RUnlock()
			b.stats["cache_hit"]++
			results[i] = result
			continue
		}
		b.mu.RUnlock()

		// Regex tiers locally
		isSuspicious := false
		for _, pat := range SecretRemovalPatterns {
			if pat.MatchString(key) {
				b.stats["patterns"]++
				isSuspicious = true
				break
			}
		}
		if !isSuspicious {
			for _, pat := range GitCredSweepPatterns {
				if pat.MatchString(key) {
					b.stats["patterns"]++
					isSuspicious = true
					break
				}
			}
		}

		if !isSuspicious {
			words := tokenize(key)
			hv, hn, bv, bn := false, false, false, false
			for w := range words {
				if HighConfidenceActionVerbs[w] {
					hv = true
				}
				if HighConfidenceObjectNouns[w] {
					hn = true
				}
				if BroadActionVerbs[w] {
					bv = true
				}
				if BroadObjectNouns[w] {
					bn = true
				}
			}
			if hv && hn {
				b.stats["regex_tier1"]++
				isSuspicious = true
			} else if bv && bn {
				b.stats["regex_tier2"]++
				isSuspicious = true
			}
		}

		if isSuspicious {
			results[i] = Suspicious
			b.mu.Lock()
			b.cache[key] = Suspicious
			b.mu.Unlock()
		} else {
			ambiguous = append(ambiguous, pending{idx: i, msg: msg})
		}
	}

	// Batch LLM call for all ambiguous
	if len(ambiguous) > 0 && b.hasLLM {
		var llmMsgs []string
		for _, p := range ambiguous {
			llmMsgs = append(llmMsgs, p.msg)
		}
		batchResult, err := b.llm.ClassifyBatch(llmMsgs)
		if err != nil {
			log.Printf("LLM batch error: %v", err)
		}
		for listIdx, p := range ambiguous {
			res := Clean
			if batchResult != nil {
				if r, ok := batchResult[listIdx]; ok && r == Suspicious {
					res = Suspicious
				}
			}
			results[p.idx] = res
			b.mu.Lock()
			b.cache[strings.ToLower(strings.TrimSpace(p.msg))] = res
			b.mu.Unlock()
			b.stats["llm"]++
		}
	} else {
		for _, p := range ambiguous {
			results[p.idx] = Clean
			b.mu.Lock()
			b.cache[strings.ToLower(strings.TrimSpace(p.msg))] = Clean
			b.mu.Unlock()
		}
	}

	// Fill any nil entries
	for i, r := range results {
		if r == "" {
			results[i] = Clean
		}
	}

	return results
}

// ── Helpers ────────────────────────────────────────────────────────

func tokenize(s string) map[string]bool {
	words := make(map[string]bool)
	for _, match := range tokenPattern.FindAllString(strings.ToLower(s), -1) {
		words[match] = true
	}
	return words
}
