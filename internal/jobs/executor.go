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
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nodejs"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/wordpress"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

const maxConcurrentJobs = 4

// Executor processes agent jobs with concurrency control.
type Executor struct {
	cfg           *config.Config
	encryptionKey []byte // AES-256; nil = no decryption attempted
	nginx         *nginx.Manager
	prov          *provisioning.Provisioner
	wpProv        *wordpress.Provisioner
	jsProv        *nodejs.Provisioner
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
		cfg:           cfg,
		encryptionKey: key,
		nginx:         nginx.NewManager(),
		prov:          provisioning.NewProvisioner(),
		wpProv:        wordpress.New(cfg),
		jsProv:        nodejs.New(cfg),
		semaphore:     make(chan struct{}, maxConcurrentJobs),
		activeJobs:    make(map[string]bool),
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
// The fourth argument to onComplete is an optional JSON string of provisioning
// outputs (subdomain, admin credentials) to be relayed to the API.
func (e *Executor) ProcessJobs(
	ctx context.Context,
	jobs []*wardenv1.AgentJob,
	onComplete func(jobID string, status wardenv1.ProvisioningStatus, errMsg string, resultJSON string),
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
			status, errMsg, resultJSON := e.executeJob(ctx, j)
			log.Printf("[jobs] job %s finished — status %s", j.JobId, status)

			if onComplete != nil {
				onComplete(j.JobId, status, errMsg, resultJSON)
			}
		}(job)
	}
}

// executeJob decrypts the payload (if present) and dispatches to the correct handler.
// Returns (status, errMsg, resultJSON). resultJSON is non-empty only for successful
// provisioning jobs and carries outputs like subdomain and admin credentials.
func (e *Executor) executeJob(ctx context.Context, job *wardenv1.AgentJob) (
	wardenv1.ProvisioningStatus, string, string,
) {
	var payload map[string]interface{}
	if len(job.EncryptedPayload) > 0 {
		// The v2 API queues jobs with a raw JSON payload (stored in agent_jobs.payload::jsonb).
		// Encrypted payloads are reserved for future direct-gRPC flows. Try JSON first —
		// if it parses as an object, use it; otherwise attempt AES-GCM decryption.
		if p, ok := tryParseJSONPayload(job.EncryptedPayload); ok {
			payload = p
		} else {
			p, err := e.decryptPayload(job.EncryptedPayload)
			if err != nil {
				return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
					fmt.Sprintf("decrypt payload: %v", err), ""
			}
			payload = p
		}
	}

	// wrap2 converts (status, errMsg) handlers to the three-value form.
	wrap2 := func(status wardenv1.ProvisioningStatus, errMsg string) (wardenv1.ProvisioningStatus, string, string) {
		return status, errMsg, ""
	}

	switch job.Type {
	case wardenv1.JobType_JOB_TYPE_PROVISION_WORDPRESS,
		wardenv1.JobType_JOB_TYPE_PROVISION_PHP:
		return e.handleProvisionSite(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_PROVISION_NODEJS:
		return e.handleProvisionNodeJS(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_DEPROVISION_SITE:
		return wrap2(e.handleDeprovisionSiteJob(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_BACKUP_SITE:
		return wrap2(e.handleBackupSite(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_RESTORE_SITE:
		return wrap2(e.handleRestoreSite(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_SUSPEND_SITE:
		return wrap2(e.handleSuspendSite(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_UNSUSPEND_SITE:
		return wrap2(e.handleUnsuspendSite(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_SCAN_MALWARE:
		return wrap2(e.handleScanMalware(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_CHANGE_PHP_VERSION:
		return wrap2(e.handleChangePHPVersion(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_PURGE_CACHE:
		return wrap2(e.handlePurgeCache(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_SYNC_WAF_RULES:
		return wrap2(e.handleSyncWafRules(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_SYNC_MU_PLUGINS:
		return wrap2(e.handleSyncMuPlugins(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_RELOAD_NGINX:
		return wrap2(e.handleReloadNginx(ctx))

	case wardenv1.JobType_JOB_TYPE_ISSUE_CERTIFICATE:
		return wrap2(e.handleIssueCertificate(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_CLONE_FILES:
		return wrap2(e.handleCloneFiles(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_PUSH_TO_PRODUCTION:
		return wrap2(e.handlePushToProduction(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_MIGRATE_SITE:
		return wrap2(e.handleMigrateSite(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_CONVERT_V1_TO_V2:
		return wrap2(e.handleConvertV1ToV2(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_DOCKER_RESTART:
		return wrap2(e.handleDockerRestart(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_DOCKER_STOP:
		return wrap2(e.handleDockerStop(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_DOCKER_LOGS:
		return wrap2(e.handleDockerLogs(ctx, payload))

	case wardenv1.JobType_JOB_TYPE_SYNC_CLEANUP_SCRIPT,
		wardenv1.JobType_JOB_TYPE_RUN_WP_CLI:
		// These are handled by the heartbeat sync path or direct invocation.
		log.Printf("[jobs] job type %s not implemented in executor fallback", job.Type)
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, "", ""

	default:
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("unknown job type: %s", job.Type), ""
	}
}

// tryParseJSONPayload returns (payload, true) when data is valid JSON object.
// Used as the first attempt before falling through to AES-GCM decryption.
func tryParseJSONPayload(data []byte) (map[string]interface{}, bool) {
	trimmed := []byte{}
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		trimmed = append(trimmed, b)
		if len(trimmed) > 0 {
			break
		}
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, false
	}
	return payload, true
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
