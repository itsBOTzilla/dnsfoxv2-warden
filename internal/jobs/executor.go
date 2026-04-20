// Package jobs processes AgentJob messages delivered via the heartbeat response.
// These are operational jobs that do not have dedicated gRPC RPCs:
// SYNC_WAF_RULES, SYNC_MU_PLUGINS, RELOAD_NGINX, ISSUE_CERTIFICATE.
// Provisioning jobs (PROVISION_*, DEPROVISION_*) arrive via direct gRPC calls
// and are only listed here for fallback completeness.
//
// Concurrency is bounded by maxConcurrentJobs; duplicate job IDs are skipped.
// Each job's encrypted_payload is decrypted with AES-256-GCM before dispatch.
package jobs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

const maxConcurrentJobs = 4

// Executor processes agent jobs with concurrency control.
type Executor struct {
	cfg           *config.Config
	encryptionKey []byte // AES-256; nil = no decryption attempted
	nginx         *nginx.Manager
	semaphore     chan struct{}
	mu            sync.Mutex
	activeJobs    map[string]bool
}

// NewExecutor creates a job executor. encryptionKey may be empty when the
// WARDEN_PAYLOAD_ENCRYPTION_KEY env var is not set; jobs with encrypted payloads
// will fail with a clear error in that case.
func NewExecutor(cfg *config.Config) *Executor {
	var key []byte
	if cfg.PayloadEncryptionKey != "" {
		b, err := hex.DecodeString(cfg.PayloadEncryptionKey)
		if err == nil && len(b) == 32 {
			key = b
		} else {
			log.Printf("[jobs] warn: WARDEN_PAYLOAD_ENCRYPTION_KEY is set but invalid — encrypted jobs will fail")
		}
	}
	return &Executor{
		cfg:        cfg,
		encryptionKey: key,
		nginx:      nginx.NewManager(),
		semaphore:  make(chan struct{}, maxConcurrentJobs),
		activeJobs: make(map[string]bool),
	}
}

// ActiveJobCount returns the number of currently running jobs.
func (e *Executor) ActiveJobCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.activeJobs)
}

// ProcessJobs dispatches a batch of jobs received from the heartbeat response.
// Each job runs in its own goroutine, bounded by maxConcurrentJobs.
// onComplete is called when each job finishes (success or failure).
func (e *Executor) ProcessJobs(
	ctx context.Context,
	jobs []*wardenv1.AgentJob,
	onComplete func(jobID string, status wardenv1.ProvisioningStatus, errMsg string),
) {
	for _, job := range jobs {
		e.mu.Lock()
		if e.activeJobs[job.JobId] {
			e.mu.Unlock()
			continue // already running
		}
		e.activeJobs[job.JobId] = true
		e.mu.Unlock()

		go func(j *wardenv1.AgentJob) {
			e.semaphore <- struct{}{}
			defer func() {
				<-e.semaphore
				e.mu.Lock()
				delete(e.activeJobs, j.JobId)
				e.mu.Unlock()
			}()

			log.Printf("[jobs] starting job %s type %s", j.JobId, j.Type)
			status, errMsg := e.executeJob(ctx, j)
			log.Printf("[jobs] job %s finished — status %s", j.JobId, status)

			if onComplete != nil {
				onComplete(j.JobId, status, errMsg)
			}
		}(job)
	}
}

// executeJob decrypts the payload (if present) and dispatches to the correct handler.
func (e *Executor) executeJob(ctx context.Context, job *wardenv1.AgentJob) (
	wardenv1.ProvisioningStatus, string,
) {
	var payload map[string]interface{}
	if len(job.EncryptedPayload) > 0 {
		p, err := e.decryptPayload(job.EncryptedPayload)
		if err != nil {
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
				fmt.Sprintf("decrypt payload: %v", err)
		}
		payload = p
	}

	switch job.Type {
	case wardenv1.JobType_JOB_TYPE_PROVISION_WORDPRESS,
		wardenv1.JobType_JOB_TYPE_PROVISION_PHP:
		return e.handleProvisionSite(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_PROVISION_NODEJS:
		return e.handleProvisionNodeJS(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_DEPROVISION_SITE:
		return e.handleDeprovisionSite(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_PURGE_CACHE:
		return e.handlePurgeCache(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_SYNC_WAF_RULES:
		return e.handleSyncWafRules(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_SYNC_MU_PLUGINS:
		return e.handleSyncMuPlugins(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_RELOAD_NGINX:
		return e.handleReloadNginx(ctx)

	case wardenv1.JobType_JOB_TYPE_ISSUE_CERTIFICATE:
		return e.handleIssueCertificate(ctx, payload)

	default:
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("unknown job type: %s", job.Type)
	}
}

// decryptPayload decrypts an AES-256-GCM encrypted job payload and unmarshals it.
func (e *Executor) decryptPayload(encrypted []byte) (map[string]interface{}, error) {
	if len(e.encryptionKey) == 0 {
		return nil, fmt.Errorf("no payload encryption key configured")
	}
	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("payload too short (%d bytes)", len(encrypted))
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	return payload, nil
}
