package internal

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ── GitAPIClient ───────────────────────────────────────────────────

type GitAPIClient struct {
	Token     string
	APIBase   string
	ForgeType string
	client    *http.Client
	diffCache map[string]string
	msgCache  map[string]string
	mu        sync.RWMutex

	// Rate-limit state protected by rateMu
	rateMu    sync.Mutex
	apiCalls  int
	rateLimit int
	rateReset time.Time
}

func NewGitAPIClient(token, apiBase, forgeType string) *GitAPIClient {
	if apiBase == "" {
		apiBase = ForgeAPIDefaults[forgeType]
		if apiBase == "" {
			apiBase = GHAPIBase
		}
	}
	return &GitAPIClient{
		Token:     token,
		APIBase:   apiBase,
		ForgeType: forgeType,
		client:    &http.Client{Timeout: 30 * time.Second},
		diffCache: make(map[string]string),
		msgCache:  make(map[string]string),
		rateLimit: 5000,
		rateReset: time.Now(),
	}
}

func (g *GitAPIClient) commitURL(owner, repo, sha string) string {
	ft := g.ForgeType
	switch ft {
	case "gitlab":
		return fmt.Sprintf("%s/projects/%s%%2F%s/repository/commits/%s", g.APIBase, owner, repo, sha)
	case "bitbucket":
		return fmt.Sprintf("%s/repositories/%s/%s/commit/%s", g.APIBase, owner, repo, sha)
	case "azure_devops":
		return fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/commits/%s?api-version=7.0", g.APIBase, owner, repo, repo, sha)
	case "sourceforge":
		return fmt.Sprintf("%s/p/%s/%s/git/commits/%s", g.APIBase, owner, repo, sha)
	default:
		return fmt.Sprintf("%s/repos/%s/%s/commits/%s", g.APIBase, owner, repo, sha)
	}
}

func (g *GitAPIClient) diffURL(owner, repo, sha string) string {
	ft := g.ForgeType

	// PR diff routing
	if strings.HasPrefix(sha, "pr-") {
		prNum := strings.TrimPrefix(sha, "pr-")
		switch ft {
		case "github":
			return fmt.Sprintf("%s/repos/%s/%s/pulls/%s", g.APIBase, owner, repo, prNum)
		case "gitlab":
			return fmt.Sprintf("%s/projects/%s%%2F%s/merge_requests/%s/diffs", g.APIBase, owner, repo, prNum)
		case "gitea", "gogs":
			return fmt.Sprintf("%s/repos/%s/%s/pulls/%s.diff", g.APIBase, owner, repo, prNum)
		default:
			return fmt.Sprintf("%s/repos/%s/%s/commits/%s", g.APIBase, owner, repo, sha)
		}
	}

	base := g.commitURL(owner, repo, sha)
	switch ft {
	case "gitlab":
		return base + "/diff"
	case "bitbucket":
		return base + "/diff"
	case "azure_devops":
		return base + "/changes?api-version=7.0"
	default:
		return base
	}
}

func (g *GitAPIClient) checkRateLimit() {
	g.rateMu.Lock()
	defer g.rateMu.Unlock()
	if g.rateLimit > 0 {
		return
	}
	now := time.Now()
	if now.Before(g.rateReset) {
		sleep := g.rateReset.Sub(now) + time.Second
		log.Printf("Rate limit exhausted, sleeping %.0fs", sleep.Seconds())
		g.rateMu.Unlock()
		time.Sleep(sleep)
		g.rateMu.Lock()
	}
	g.rateLimit = 5000
	g.rateReset = time.Now().Add(time.Hour)
}

// proactiveRateCheck queries the GitHub rate_limit API when nearing exhaustion.
func (g *GitAPIClient) proactiveRateCheck() {
	if g.ForgeType != "github" {
		return
	}
	g.rateMu.Lock()
	if g.rateLimit > 100 {
		g.rateMu.Unlock()
		return
	}
	g.rateMu.Unlock()

	req, err := http.NewRequest("GET", GHAPIBase+"/rate_limit", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", UserAgent)
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}
	var body struct {
		Resources struct {
			Core struct {
				Remaining int     `json:"remaining"`
				Reset     float64 `json:"reset"`
			} `json:"core"`
		} `json:"resources"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return
	}
	g.rateMu.Lock()
	g.rateLimit = body.Resources.Core.Remaining
	g.rateReset = time.Unix(int64(body.Resources.Core.Reset), 0)
	g.rateMu.Unlock()
}

func (g *GitAPIClient) decRateLimit() {
	g.rateMu.Lock()
	g.apiCalls++
	g.rateLimit--
	g.rateMu.Unlock()
}

func (g *GitAPIClient) fetchWithAuth(urlStr string, acceptHeader string) (string, error) {
	g.checkRateLimit()

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	if acceptHeader != "" {
		req.Header.Set("Accept", acceptHeader)
	}

	ft := g.ForgeType
	if g.Token != "" {
		switch ft {
		case "gitlab":
			req.Header.Set("PRIVATE-TOKEN", g.Token)
		case "azure_devops":
			auth := base64Encode(":" + g.Token)
			req.Header.Set("Authorization", "Basic "+auth)
		default:
			req.Header.Set("Authorization", "Bearer "+g.Token)
		}
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	g.decRateLimit()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			g.rateMu.Lock()
			g.rateLimit = 0
			g.rateReset = time.Now().Add(time.Minute)
			g.rateMu.Unlock()
		}
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

func (g *GitAPIClient) fetchWithAuthAndStatus(urlStr, acceptHeader string) (string, int, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if acceptHeader != "" {
		req.Header.Set("Accept", acceptHeader)
	}

	ft := g.ForgeType
	if g.Token != "" {
		switch ft {
		case "gitlab":
			req.Header.Set("PRIVATE-TOKEN", g.Token)
		case "azure_devops":
			auth := base64Encode(":" + g.Token)
			req.Header.Set("Authorization", "Basic "+auth)
		default:
			req.Header.Set("Authorization", "Bearer "+g.Token)
		}
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		g.rateMu.Lock()
		g.rateLimit = 0
		g.rateReset = time.Now().Add(time.Minute)
		g.rateMu.Unlock()
	}
	return string(body), resp.StatusCode, nil
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func (g *GitAPIClient) extractMessage(body, forgeType string) string {
	var msg string
	switch forgeType {
	case "github":
		var resp struct {
			Commit struct {
				Message string `json:"message"`
			} `json:"commit"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			msg = resp.Commit.Message
		}
	case "gitlab":
		var resp struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			msg = resp.Message
		}
	case "bitbucket":
		var resp struct {
			Summary struct {
				Raw string `json:"raw"`
			} `json:"summary"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			msg = resp.Summary.Raw
		}
	case "azure_devops":
		var resp struct {
			Comment string `json:"comment"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			msg = resp.Comment
		}
	case "sourceforge":
		var resp struct {
			Message string `json:"message"`
			Title   string `json:"title"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			msg = resp.Message
			if msg == "" {
				msg = resp.Title
			}
		}
	default:
		var resp struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err == nil {
			msg = resp.Message
		}
	}
	if idx := strings.IndexByte(msg, '\n'); idx != -1 {
		msg = msg[:idx]
	}
	return msg
}

func (g *GitAPIClient) FetchCommitMessage(owner, repo, sha string) (string, error) {
	key := fmt.Sprintf("%s/%s/%s", owner, repo, sha)
	g.mu.RLock()
	if cached, ok := g.msgCache[key]; ok {
		g.mu.RUnlock()
		if cached == "" {
			return "", fmt.Errorf("commit message not found (cached miss): %s", key)
		}
		return cached, nil
	}
	g.mu.RUnlock()

	if g.ForgeType == "codecommit" {
		return g.fetchCodeCommitMsg(owner, repo, sha)
	}

	g.checkRateLimit()
	g.proactiveRateCheck()

	url := g.commitURL(owner, repo, sha)
	accept := "application/vnd.github.v3+json"
	if g.ForgeType == "gitlab" {
		accept = "application/json"
	}

	body, statusCode, err := g.fetchWithAuthAndStatus(url, accept)
	if err != nil {
		return "", err
	}
	g.decRateLimit()

	if statusCode == 200 {
		msg := g.extractMessage(body, g.ForgeType)
		if msg != "" {
			g.mu.Lock()
			g.msgCache[key] = msg
			g.mu.Unlock()
			return msg, nil
		}
		g.mu.Lock()
		g.msgCache[key] = msg // cache empty string
		g.mu.Unlock()
		return "", fmt.Errorf("unable to parse commit message from %s", url)
	}
	if statusCode == 403 || statusCode == 429 {
		g.proactiveRateCheck()
		return "", fmt.Errorf("rate limited (HTTP %d)", statusCode)
	}
	if statusCode == 404 {
		g.mu.Lock()
		g.msgCache[key] = ""
		g.mu.Unlock()
		return "", fmt.Errorf("commit not found (HTTP 404): %s", url)
	}
	return "", fmt.Errorf("commit message fetch failed (HTTP %d)", statusCode)
}

func (g *GitAPIClient) fetchCodeCommitMsg(owner, repo, sha string) (string, error) {
	cloneURL := fmt.Sprintf("https://%s@git-codecommit.%s.amazonaws.com/v1/repos/%s", g.Token, owner, repo)
	dir, err := os.MkdirTemp("", "codecommit-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	cmd := exec.Command("git", "clone", "--depth", "1", cloneURL, dir)
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("codecommit clone failed: %w", err)
	}
	out, err := exec.Command("git", "-C", dir, "log", "--format=%s", "-1", sha).Output()
	if err != nil {
		return "", fmt.Errorf("codecommit log failed: %w", err)
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return "", fmt.Errorf("codecommit commit not found: %s", sha)
	}
	return msg, nil
}

func (g *GitAPIClient) fetchCodeCommitDiff(owner, repo, sha string) (string, error) {
	cloneURL := fmt.Sprintf("https://%s@git-codecommit.%s.amazonaws.com/v1/repos/%s", g.Token, owner, repo)
	dir, err := os.MkdirTemp("", "codecommit-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	cmd := exec.Command("git", "clone", "--depth", "1", cloneURL, dir)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("codecommit clone failed: %w", err)
	}
	out, err := exec.Command("git", "-C", dir, "show", "--format=full", sha).Output()
	if err != nil {
		return "", fmt.Errorf("codecommit diff failed: %w", err)
	}
	return string(out), nil
}

func (g *GitAPIClient) FetchDiff(owner, repo, sha string) (string, error) {
	cacheKey := fmt.Sprintf("%s/%s/%s", owner, repo, sha)
	g.mu.RLock()
	if d, ok := g.diffCache[cacheKey]; ok {
		g.mu.RUnlock()
		return d, nil
	}
	g.mu.RUnlock()

	if g.ForgeType == "codecommit" {
		return g.fetchCodeCommitDiff(owner, repo, sha)
	}

	url := g.diffURL(owner, repo, sha)
	accept := "application/vnd.github.v3.diff"
	if g.ForgeType == "gitlab" || g.ForgeType == "azure_devops" {
		accept = "application/json"
	} else if g.ForgeType == "gitea" || g.ForgeType == "gogs" {
		accept = "application/vnd.git.diff"
	} else if g.ForgeType == "bitbucket" {
		accept = "application/x.diff"
	} else if g.ForgeType == "sourceforge" {
		accept = "application/vnd.git.diff"
	}

	body, err := g.fetchWithAuth(url, accept)
	if err != nil {
		return "", err
	}

	diff := extractDiff(body, g.ForgeType)
	g.mu.Lock()
	g.diffCache[cacheKey] = diff
	g.mu.Unlock()
	return diff, nil
}

func extractDiff(body, forgeType string) string {
	ct := "text/plain"

	if forgeType == "gitlab" && isJSON(body) {
		var raw []struct {
			OldPath string `json:"old_path"`
			NewPath string `json:"new_path"`
			Diff    string `json:"diff"`
		}
		if json.Unmarshal([]byte(body), &raw) == nil {
			var lines []string
			for _, d := range raw {
				lines = append(lines, fmt.Sprintf("diff --git a/%s b/%s", d.OldPath, d.NewPath))
				lines = append(lines, fmt.Sprintf("--- a/%s", d.OldPath))
				lines = append(lines, fmt.Sprintf("+++ b/%s", d.NewPath))
				if d.Diff != "" {
					lines = append(lines, d.Diff)
				}
			}
			return strings.Join(lines, "\n")
		}
	}

	if forgeType == "bitbucket" && isJSON(body) {
		var raw struct {
			Values []struct {
				Old  map[string]string `json:"old"`
				New  map[string]string `json:"new"`
				Diff string            `json:"diff"`
			} `json:"values"`
		}
		if json.Unmarshal([]byte(body), &raw) == nil {
			var lines []string
			for _, d := range raw.Values {
				oldPath := d.Old["path"]
				newPath := d.New["path"]
				lines = append(lines, fmt.Sprintf("diff --git a/%s b/%s", oldPath, newPath))
				if d.Diff != "" {
					lines = append(lines, d.Diff)
				}
			}
			return strings.Join(lines, "\n")
		}
	}

	if forgeType == "azure_devops" && isJSON(body) {
		var raw struct {
			Changes []struct {
				Item map[string]string `json:"item"`
				Diff string            `json:"diff"`
			} `json:"changes"`
		}
		if json.Unmarshal([]byte(body), &raw) == nil {
			var lines []string
			for _, ch := range raw.Changes {
				path := ch.Item["path"]
				lines = append(lines, fmt.Sprintf("diff --git a/%s b/%s", path, path))
				if ch.Diff != "" {
					lines = append(lines, ch.Diff)
				}
			}
			return strings.Join(lines, "\n")
		}
	}

	_ = ct
	return body
}

func isJSON(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) > 0 && (s[0] == '{' || s[0] == '[')
}

func (g *GitAPIClient) Close() {}

// ── Standalone helpers ─────────────────────────────────────────────

func cloneRepo(repoURL, ref string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "ghleak_")
	if err != nil {
		return "", fmt.Errorf("temp dir: %w", err)
	}
	log.Printf("Cloning %s @ %s into %s", repoURL, ref, tmpDir)
	clone := exec.Command("git", "clone", "--depth", "1", "--single-branch", repoURL, tmpDir)
	if out, err := clone.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if ref != "" && ref != "HEAD" {
		checkout := exec.Command("git", "-C", tmpDir, "checkout", ref)
		if out, err := checkout.CombinedOutput(); err != nil {
			return "", fmt.Errorf("git checkout %s: %s: %w", ref, strings.TrimSpace(string(out)), err)
		}
	}
	return tmpDir, nil
}

type RepoParts struct {
	Protocol string
	Host     string
	Owner    string
	Repo     string
	Full     string
}

func gitURLParts(rawURL string) RepoParts {
	rawURL = strings.TrimSpace(rawURL)
	parts := RepoParts{}

	var path string

	if strings.HasPrefix(rawURL, "git@") || strings.HasPrefix(rawURL, "ssh://") {
		parts.Protocol = "ssh"
		if strings.Contains(rawURL, "://") {
			rest := strings.SplitN(rawURL, "://", 2)[1]
			atParts := strings.SplitN(rest, "@", 2)
			afterAt := rest
			if len(atParts) > 1 {
				afterAt = atParts[1]
			}
			slashIdx := strings.IndexByte(afterAt, '/')
			if slashIdx != -1 {
				parts.Host = afterAt[:slashIdx]
				path = afterAt[slashIdx+1:]
			}
		} else {
			atIdx := strings.IndexByte(rawURL, '@')
			afterAt := rawURL
			if atIdx != -1 {
				afterAt = rawURL[atIdx+1:]
			}
			colonIdx := strings.IndexByte(afterAt, ':')
			if colonIdx != -1 {
				parts.Host = afterAt[:colonIdx]
				path = afterAt[colonIdx+1:]
			}
		}
	} else if strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://") {
		if strings.HasPrefix(rawURL, "https://") {
			parts.Protocol = "https"
		} else {
			parts.Protocol = "http"
		}
		rest := strings.SplitN(rawURL, "://", 2)[1]
		slashIdx := strings.IndexByte(rest, '/')
		if slashIdx != -1 {
			parts.Host = rest[:slashIdx]
			path = rest[slashIdx+1:]
		} else {
			parts.Host = rest
		}
	}

	path = strings.TrimSuffix(path, ".git")
	pathParts := strings.SplitN(path, "/", 2)
	if len(pathParts) >= 2 {
		parts.Owner = pathParts[0]
		parts.Repo = pathParts[1]
	}
	parts.Full = parts.Host + "/" + path
	return parts
}

func resolveRepoURL(repoName, forge string) string {
	m := map[string]string{
		"github":    fmt.Sprintf("https://github.com/%s.git", repoName),
		"gitlab":    fmt.Sprintf("https://gitlab.com/%s.git", repoName),
		"gitea":     fmt.Sprintf("https://gitea.com/%s.git", repoName),
		"gogs":      fmt.Sprintf("https://try.gogs.io/%s.git", repoName),
		"bitbucket": fmt.Sprintf("https://bitbucket.org/%s.git", repoName),
	}
	if u, ok := m[forge]; ok {
		return u
	}
	return fmt.Sprintf("https://%s/%s.git", forge, repoName)
}

// ── GH Archive helpers ─────────────────────────────────────────────

func ArchiveHourURL(dt time.Time) string {
	return fmt.Sprintf("%s/%s.json.gz", GHArchiveBase, dt.Format("2006-01-02-15"))
}

func FetchArchive(urlStr string) ([]map[string]interface{}, error) {
	log.Printf("Fetching %s", urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("archive get: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("archive HTTP %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gzr.Close()

	dec := json.NewDecoder(gzr)
	var events []map[string]interface{}
	for {
		var ev map[string]interface{}
		if err := dec.Decode(&ev); err == io.EOF {
			break
		} else if err != nil {
			continue
		}
		events = append(events, ev)
	}

	return events, nil
}

func FetchArchiveStream(urlStr string) (<-chan map[string]interface{}, error) {
	ch := make(chan map[string]interface{}, 1024)

	resp, err := http.Get(urlStr)
	if err != nil {
		close(ch)
		return ch, fmt.Errorf("archive get: %w", err)
	}

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		close(ch)
		return ch, fmt.Errorf("archive HTTP %d", resp.StatusCode)
	}

	go func() {
		defer func() {
			io.Copy(io.Discard, resp.Body) // Drain body explicitly
			resp.Body.Close()
			close(ch)
		}()

		gzr, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("gzip error: %v", err)
			return
		}
		defer gzr.Close()

		dec := json.NewDecoder(gzr)
		for {
			var ev map[string]interface{}
			if err := dec.Decode(&ev); err == io.EOF {
				break
			} else if err != nil {
				continue
			}
			ch <- ev
		}
	}()

	return ch, nil
}

// ── Event extraction ───────────────────────────────────────────────

func ExtractPushEvents(events []map[string]interface{}) []Event {
	var out []Event
	for _, ev := range events {
		if ev["type"] != "PushEvent" {
			continue
		}
		payload, _ := ev["payload"].(map[string]interface{})
		repo, _ := ev["repo"].(map[string]interface{})
		e := Event{
			EventType: "push",
			Repo:      getString(repo, "name"),
			Head:      getString(payload, "head"),
			Ref:       getString(payload, "ref"),
			Timestamp: getString(ev, "created_at"),
			IsPR:      false,
		}
		out = append(out, e)
	}
	return out
}

func ExtractPullRequestEvents(events []map[string]interface{}) []Event {
	var out []Event
	for _, ev := range events {
		if ev["type"] != "PullRequestEvent" {
			continue
		}
		payload, _ := ev["payload"].(map[string]interface{})
		if payload == nil {
			continue
		}
		action := getString(payload, "action")
		if action != "opened" && action != "reopened" {
			continue
		}
		pr, _ := payload["pull_request"].(map[string]interface{})
		repo, _ := ev["repo"].(map[string]interface{})
		e := Event{
			EventType: "pr",
			Repo:      getString(repo, "name"),
			Title:     getString(pr, "title"),
			PRNumber:  getInt(pr, "number"),
			PRURL:     getString(pr, "html_url"),
			Action:    action,
			Timestamp: getString(ev, "created_at"),
			IsPR:      true,
		}
		out = append(out, e)
	}
	return out
}

func ResolveCommitMessages(events []Event, client *GitAPIClient) []CommitInfo {
	var commits []CommitInfo
	for _, ev := range events {
		if ev.IsPR {
			if ev.Title == "" || ev.Repo == "" {
				continue
			}
			commits = append(commits, CommitInfo{
				SHA:     fmt.Sprintf("pr-%d", ev.PRNumber),
				Message: ev.Title,
				Repo:    ev.Repo,
				IsPR:    true,
				PRURL:   ev.PRURL,
				TS:      ev.Timestamp,
			})
			continue
		}

		if ev.Head == "" || ev.Repo == "" {
			continue
		}
		parts := strings.SplitN(ev.Repo, "/", 2)
		if len(parts) != 2 {
			continue
		}
		owner, repo := parts[0], parts[1]
		msg, err := client.FetchCommitMessage(owner, repo, ev.Head)
		if err != nil {
			log.Printf("Fetch message failed for %s/%s@%s: %v", owner, repo, shortSHA(ev.Head), err)
			continue
		}
		commits = append(commits, CommitInfo{
			SHA:     ev.Head,
			Message: msg,
			Repo:    ev.Repo,
			Ref:     ev.Ref,
			TS:      ev.Timestamp,
			IsPR:    false,
		})
	}
	return commits
}

// ResolveCommitMessagesConcurrent uses the fixed WorkerPool for parallel fetches
func ResolveCommitMessagesConcurrent(events []Event, client *GitAPIClient, numWorkers int) []CommitInfo {
	var prCommits []CommitInfo
	var pushEvents []Event

	for _, ev := range events {
		if ev.IsPR {
			if ev.Title != "" && ev.Repo != "" {
				prCommits = append(prCommits, CommitInfo{
					SHA: fmt.Sprintf("pr-%d", ev.PRNumber), Message: ev.Title,
					Repo: ev.Repo, IsPR: true, PRURL: ev.PRURL, TS: ev.Timestamp,
				})
			}
			continue
		}
		if ev.Head != "" && ev.Repo != "" && strings.Contains(ev.Repo, "/") {
			pushEvents = append(pushEvents, ev)
		}
	}

	results := RunWorkerPool(pushEvents, func(ev Event) *CommitInfo {
		parts := strings.SplitN(ev.Repo, "/", 2)
		msg, err := client.FetchCommitMessage(parts[0], parts[1], ev.Head)
		if err != nil {
			return nil
		}
		return &CommitInfo{
			SHA: ev.Head, Message: msg, Repo: ev.Repo,
			Ref: ev.Ref, TS: ev.Timestamp, IsPR: false,
		}
	}, numWorkers)

	var final []CommitInfo
	for _, r := range results {
		if r != nil {
			final = append(final, *r)
		}
	}
	return append(final, prCommits...)
}

// ── Standalone diff fetchers ───────────────────────────────────────

func FetchDiffFromGitHub(owner, repo, sha, token string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", GHAPIBase, owner, repo, sha)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3.diff")
	req.Header.Set("User-Agent", UserAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doHTTP(req)
}

func FetchDiffFromGitLab(projectID, sha, token string) (string, error) {
	encodedID := url.QueryEscape(projectID)
	url := fmt.Sprintf("%s/projects/%s/repository/commits/%s/diff", GitLabAPIBase, encodedID, sha)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	body, err := doHTTP(req)
	if err != nil {
		return "", err
	}
	return extractDiff(body, "gitlab"), nil
}

func FetchDiffFromGitea(owner, repo, sha, baseURL, token string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/commits/%s.diff", baseURL, owner, repo, sha)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doHTTP(req)
}

func FetchDiffFromBitbucket(owner, repo, sha, token string) (string, error) {
	url := fmt.Sprintf("%s/repositories/%s/%s/diff/%s", BitBucketAPIBase, owner, repo, sha)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/x.diff")
	req.Header.Set("User-Agent", UserAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doHTTP(req)
}

func FetchDiffFromAzureDevOps(org, project, repo, sha, token string) (string, error) {
	url := fmt.Sprintf("%s/%s/%s/_apis/git/repositories/%s/commits/%s/changes?api-version=7.0",
		AzureDevOpsAPIBase, org, project, repo, sha)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", UserAgent)
	if token != "" {
		auth := base64Encode(":" + token)
		req.Header.Set("Authorization", "Basic "+auth)
	}
	body, err := doHTTP(req)
	if err != nil {
		return "", err
	}
	return extractDiff(body, "azure_devops"), nil
}

func FetchDiffFromURL(repoURL, sha, token string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	host := strings.ToLower(u.Host)
	path := strings.Trim(u.Path, "/")
	parts := strings.SplitN(path, "/", 3)

	if len(parts) < 2 {
		return "", fmt.Errorf("cannot parse repo path from %s", repoURL)
	}

	owner := parts[0]
	repoName := parts[1]

	if strings.Contains(host, "github") {
		return FetchDiffFromGitHub(owner, repoName, sha, token)
	}
	if strings.Contains(host, "gitlab") {
		encodedID := url.QueryEscape(owner + "/" + repoName)
		return FetchDiffFromGitLab(encodedID, sha, token)
	}
	if strings.Contains(host, "gitea") || strings.Contains(host, "gogs") {
		base := fmt.Sprintf("https://%s/api/v1", host)
		return FetchDiffFromGitea(owner, repoName, sha, base, token)
	}
	if strings.Contains(host, "bitbucket") {
		return FetchDiffFromBitbucket(owner, repoName, sha, token)
	}
	if strings.Contains(host, "dev.azure") || strings.Contains(host, "azure") {
		repoStr := strings.Join(parts[1:], "/")
		project := repoName
		realRepo := repoStr
		if strings.Contains(repoStr, "/_git/") {
			split := strings.SplitN(repoStr, "/_git/", 2)
			project = split[0]
			realRepo = split[1]
		}
		return FetchDiffFromAzureDevOps(owner, project, realRepo, sha, token)
	}

	// fallback: git clone for unknown forges
	log.Printf("Unknown forge %s, falling back to clone of %s", host, repoURL)
	tmpDir, err := cloneRepo(repoURL, sha)
	if err != nil {
		return "", fmt.Errorf("clone fallback: %w", err)
	}
	show := exec.Command("git", "-C", tmpDir, "show", "--format=full", sha)
	out, err := show.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git show: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}

// ── Helpers ────────────────────────────────────────────────────────

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func getInt(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	v, _ := m[key].(float64)
	return int(v)
}

func doHTTP(req *http.Request) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func FindLatestArchiveHour() *time.Time {
	now := time.Now().UTC()
	for offset := 1; offset <= 25; offset++ {
		candidate := now.Add(-time.Duration(offset) * time.Hour)
		url := ArchiveHourURL(candidate)
		resp, err := http.Head(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return &candidate
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	return nil
}

func StreamHours(hoursBack int, enterpriseFilter interface{}) <-chan []Event {
	ch := make(chan []Event)
	now := time.Now().UTC()

	go func() {
		defer close(ch)

		probe := now.Truncate(time.Hour)
		resp, err := http.Head(ArchiveHourURL(probe))
		endHour := probe
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			latest := FindLatestArchiveHour()
			if latest != nil {
				endHour = latest.Add(time.Hour)
			} else {
				endHour = now.Add(-time.Hour)
			}
		}
		if resp != nil {
			resp.Body.Close()
		}

		startHour := endHour.Add(-time.Duration(hoursBack) * time.Hour)
		cursor := startHour.Truncate(time.Hour)
		end := endHour.Truncate(time.Hour)

		for cursor.Before(end) {
			url := ArchiveHourURL(cursor)
			eventCh, err := FetchArchiveStream(url)
			if err != nil {
				log.Printf("Failed to fetch hour %s: %v", cursor.Format("2006-01-02T15"), err)
				cursor = cursor.Add(time.Hour)
				continue
			}

			var pushes []Event
			var prevents []Event
			for ev := range eventCh {
				if ef, ok := enterpriseFilter.(interface {
					AnalyzeEvent(map[string]interface{}) (bool, string, map[string]interface{})
				}); ok {
					pass, _, _ := ef.AnalyzeEvent(ev)
					if !pass {
						continue
					}
				}

				evType, _ := ev["type"].(string)
				switch evType {
				case "PushEvent":
					payload, _ := ev["payload"].(map[string]interface{})
					repo, _ := ev["repo"].(map[string]interface{})
					pushes = append(pushes, Event{
						EventType: "push", Repo: getString(repo, "name"),
						Head: getString(payload, "head"), Ref: getString(payload, "ref"),
						Timestamp: getString(ev, "created_at"), IsPR: false,
					})
				case "PullRequestEvent":
					payload, _ := ev["payload"].(map[string]interface{})
					if payload == nil {
						continue
					}
					action := getString(payload, "action")
					if action != "opened" && action != "reopened" {
						continue
					}
					pr, _ := payload["pull_request"].(map[string]interface{})
					repo, _ := ev["repo"].(map[string]interface{})
					prevents = append(prevents, Event{
						EventType: "pr", Repo: getString(repo, "name"),
						Title: getString(pr, "title"), PRNumber: getInt(pr, "number"),
						PRURL: getString(pr, "html_url"), Action: action,
						Timestamp: getString(ev, "created_at"), IsPR: true,
					})
				}
			}

			combined := append(pushes, prevents...)
			log.Printf("Hour %s: %d push, %d PR", cursor.Format("2006-01-02T15"), len(pushes), len(prevents))
			ch <- combined

			cursor = cursor.Add(time.Hour)
		}
	}()

	return ch
}
