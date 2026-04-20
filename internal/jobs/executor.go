package jobs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

const maxConcurrentJobs = 4

// Executor processes agent jobs with concurrency control.
type Executor struct {
	encryptionKey []byte
	semaphore     chan struct{}
	mu            sync.Mutex
	activeJobs    map[string]bool
}

// NewExecutor creates a job executor with the given AES-256 key.
func NewExecutor(encryptionKey []byte) *Executor {
	return &Executor{
		encryptionKey: encryptionKey,
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

			log.Printf("executor: starting job %s type %s", j.JobId, j.Type)
			status, errMsg := e.executeJob(ctx, j)
			log.Printf("executor: job %s finished — status %s", j.JobId, status)

			if onComplete != nil {
				onComplete(j.JobId, status, errMsg)
			}
		}(job)
	}
}

func (e *Executor) executeJob(ctx context.Context, job *wardenv1.AgentJob) (
	wardenv1.ProvisioningStatus, string,
) {
	payload, err := e.decryptPayload(job.EncryptedPayload)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("decrypt payload: %v", err)
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

	case wardenv1.JobType_JOB_TYPE_RELOAD_NGINX:
		return e.handleReloadNginx(ctx, payload)

	case wardenv1.JobType_JOB_TYPE_ISSUE_CERTIFICATE:
		return e.handleIssueCertificate(ctx, payload)

	default:
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("unknown job type: %s", job.Type)
	}
}

// decryptPayload decrypts an AES-256-GCM encrypted job payload and unmarshals it.
func (e *Executor) decryptPayload(encrypted []byte) (map[string]interface{}, error) {
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

func (e *Executor) handleProvisionSite(_ context.Context, _ map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	// TODO: extract SiteConfig from payload, call provisioning.ProvisionSite
	log.Println("executor: TODO implement provision site")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

func (e *Executor) handleProvisionNodeJS(_ context.Context, _ map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	// TODO: implement Node.js provisioning
	log.Println("executor: TODO implement provision nodejs")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

func (e *Executor) handleDeprovisionSite(_ context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	// TODO: extract site_id from payload, call provisioning.DeprovisionSite
	_ = payload
	log.Println("executor: TODO implement deprovision site")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

func (e *Executor) handlePurgeCache(_ context.Context, _ map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	// TODO: rm -rf /var/cache/nginx/sites/{site_id}/*
	log.Println("executor: TODO implement purge cache")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

func (e *Executor) handleReloadNginx(_ context.Context, _ map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	// TODO: exec.Command("systemctl", "reload", "nginx")
	log.Println("executor: TODO implement reload nginx")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

func (e *Executor) handleIssueCertificate(_ context.Context, _ map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	// TODO: exec.Command("certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos")
	log.Println("executor: TODO implement issue certificate")
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}
