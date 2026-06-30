package internal

import "regexp"

// Version matches Python's ghleak.__version__
const Version = "1.1.0"

// ── API endpoints ──────────────────────────────────────────────────

const (
	GHArchiveBase      = "https://data.gharchive.org"
	GHAPIBase          = "https://api.github.com"
	GitLabAPIBase      = "https://gitlab.com/api/v4"
	GiteaAPIBase       = "https://gitea.com/api/v1"
	GogsAPIBase        = "https://try.gogs.io/api/v1"
	BitBucketAPIBase   = "https://api.bitbucket.org/2.0"
	AzureDevOpsAPIBase = "https://dev.azure.com"
	SourceForgeAPIBase = "https://sourceforge.net/rest"
	UserAgent          = "ghleak/1.0 (security research; +https://github.com)"
)

// ── LLM / AI configuration ─────────────────────────────────────────

const (
	DefaultLLMProvider = "openai"
	DefaultLLMEndpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
	DefaultLLMModel    = "gemini-2.5-flash-lite"
)

const OneShotPrompt = `Analyze the following Git commit message to determine if it is fixing a secret leak.
The message might mention revoking, removing, or rotating keys, tokens, passwords, or other credentials.
Respond with only "true" if it is highly likely to be fixing a secret leak, otherwise respond with "false".

Commit Message:
---
{commit_message}
---`

const BatchPrompt = "Analyze the following Git commit messages to determine if any of them are fixing a secret leak.\nA message is considered to be fixing a secret leak if it mentions revoking, removing, or rotating keys, tokens, passwords, or credentials.\nReturn a JSON object where each key is the numeric index of the commit message (as a string) and the value is a boolean (`true` or `false`).\nEnsure your response is only the JSON object.\n\nCommit Messages:\n---\n{messages}\n---"

// ── Forge types ────────────────────────────────────────────────────

var ForgeTypes = []string{
	"github", "gitlab", "gitea", "gogs",
	"bitbucket", "azure_devops", "codecommit", "sourceforge", "custom",
}

var ForgeAPIDefaults = map[string]string{
	"github":       GHAPIBase,
	"gitlab":       GitLabAPIBase,
	"gitea":        GiteaAPIBase,
	"gogs":         GogsAPIBase,
	"bitbucket":    BitBucketAPIBase,
	"azure_devops": AzureDevOpsAPIBase,
	"sourceforge":  SourceForgeAPIBase,
}

// ── LLM providers ──────────────────────────────────────────────────

var LLMProviders = []string{"openai", "gemini", "anthropic", "custom"}

// ── Compiled regex patterns ────────────────────────────────────────

var SecretRemovalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(remove|delete|revoke|invalidate|rotate|regenerate)\b.*\b(key|token|secret|password|credential)\b`),
	regexp.MustCompile(`(?i)\b(fix|patch)\b.*\b(leak|expose|compromise)\b`),
	regexp.MustCompile(`(?i)\b(revert)\b.*for.*security.*reason`),
}

var GitCredSweepPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bremove\s+(hard[-\s]?)?coded\b`),
	regexp.MustCompile(`(?i)\b(rm|remove|delete)\s+\.env\b`),
	regexp.MustCompile(`(?i)\brotate\s+(all\s+)?(api\s+)?keys?\b`),
	regexp.MustCompile(`(?i)\b(pushed|commit|added)\s+(by\s+)?mistake\b`),
	regexp.MustCompile(`(?i)\bthis\s+is\s+not\s+(a\s+)?real\b`),
	regexp.MustCompile(`(?i)\breplace\s+(with|your|actual)\b`),
	regexp.MustCompile(`(?i)\bsecurity\s+fix\b`),
	regexp.MustCompile(`(?i)\bcredentials?\s+leak`),
	regexp.MustCompile(`(?i)\bsecret\s+(exposure|exposed|in code)`),
}

// ── Word lists for regex tiers ─────────────────────────────────────

var HighConfidenceActionVerbs = map[string]bool{
	"remove": true, "delete": true, "revoke": true, "invalidate": true,
	"rotate": true, "regenerate": true, "leak": true, "expose": true,
	"compromise": true,
}

var HighConfidenceObjectNouns = map[string]bool{
	"api_key": true, "apikey": true, "access_token": true, "auth_token": true,
	"private_key": true, "secret_key": true, "client_secret": true,
	"credential": true, "credentials": true, "password": true, "passwd": true,
	"aws_secret": true, "aws_access_key": true, ".env": true, "dotenv": true,
}

var BroadActionVerbs = map[string]bool{
	"update": true, "change": true, "fix": true, "patch": true, "clean": true,
	"remove": true, "delete": true, "purge": true, "wipe": true, "scrub": true,
	"strip": true, "clear": true, "sanitize": true, "redact": true, "hide": true,
}

var BroadObjectNouns = map[string]bool{
	"key": true, "token": true, "secret": true, "password": true, "credential": true,
	"aws": true, "amazon": true, "gcp": true, "google": true, "azure": true, "oauth": true,
	"openai": true, "anthropic": true, "stripe": true, "twilio": true, "sendgrid": true,
	"mailgun": true, "slack": true, "discord": true, "telegram": true, "github_pat": true,
	"gitlab": true, "datadog": true, "newrelic": true, "cloudflare": true, "algolia": true,
	"mongodb": true, "postgres": true, "mysql": true, "redis": true, "snowflake": true,
	"jwt": true, "bearer": true, "firebase": true, "supabase": true, "vercel": true,
	"netlify": true, "heroku": true, "digitalocean": true, "doppler": true,
	"hashicorp": true, "vault": true, "docker": true, "kubernetes": true, "k8s": true,
	"wandb": true, "weights_and_biases": true, "weights & biases": true,
	"huggingface": true, "deepseek": true, "groq": true, "elevenlabs": true,
	"cohere": true, "replicate": true, "together": true, "perplexity": true,
	"cloudinary": true, "dropbox": true, "box": true, "pagerduty": true,
	"sentry": true, "rollbar": true, "logz": true, "logdna": true, "papertrail": true,
	"s3": true, "ec2": true, "iam": true, "rds": true, "ses": true, "sns": true, "sqs": true,
	"cloudfront": true, "route53": true, "lambda": true, "eks": true, "ecr": true,
}

// ── TruffleHog detectors list ──────────────────────────────────────

var TrufflehogDetectors = []string{
	"aws", "gcp", "azure", "github", "gitlab", "slack",
	"discord", "telegram", "openai", "anthropic", "stripe",
	"twilio", "sendgrid", "mailgun", "datadog", "newrelic",
	"pagerduty", "sentry", "cloudflare", "algolia",
	"mongodb", "postgresql", "mysql", "redis", "snowflake",
	"jwt", "firebase", "supabase", "vercel", "netlify",
	"heroku", "docker", "kubernetes", "hashicorp",
	"huggingface", "cohere", "replicate", "together",
	"perplexity", "cloudinary", "dropbox",
	"weights_and_biases", "deepseek", "groq", "elevenlabs",
	"artifactory", "jfrog", "npm", "pypi", "rubygems",
	"grafana", "consul", "vault", "okta", "auth0",
}
