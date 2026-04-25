// Package backup — b2.go provides a minimal Backblaze B2 HTTP client.
// No SDK dependency; uses the native B2 API v3 endpoints directly.
package backup

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec — B2 API requires SHA-1
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// b2Client holds an authorised B2 session.
type b2Client struct {
	apiURL        string
	authToken     string
	downloadURL   string
	bucketID      string
	httpClient    *http.Client
}

type b2AuthResp struct {
	AccountID string `json:"accountId"`
	APIInfo   struct {
		StorageAPI struct {
			APIURL      string `json:"apiUrl"`
			DownloadURL string `json:"downloadUrl"`
		} `json:"storageApi"`
	} `json:"apiInfo"`
	AuthorizationToken string `json:"authorizationToken"`
	// Allowed is populated when the application key is restricted to a specific bucket.
	Allowed struct {
		BucketID string `json:"bucketId"`
	} `json:"allowed"`
}

type b2GetUploadURLResp struct {
	UploadURL          string `json:"uploadUrl"`
	AuthorizationToken string `json:"authorizationToken"`
}

type b2UploadResp struct {
	FileID   string `json:"fileId"`
	FileName string `json:"fileName"`
}

type b2ListBucketsResp struct {
	Buckets []struct {
		BucketID   string `json:"bucketId"`
		BucketName string `json:"bucketName"`
	} `json:"buckets"`
}

// newB2Client authorises against the B2 API and returns a ready client.
func newB2Client(ctx context.Context, keyID, appKey, bucketName string) (*b2Client, error) {
	hc := &http.Client{Timeout: 60 * time.Second}

	creds := base64.StdEncoding.EncodeToString([]byte(keyID + ":" + appKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.backblazeb2.com/b2api/v3/b2_authorize_account", nil)
	if err != nil {
		return nil, fmt.Errorf("b2 auth request: %w", err)
	}
	req.Header.Set("Authorization", "Basic "+creds)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("b2 auth: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("b2 auth HTTP %d: %s", resp.StatusCode, body)
	}

	var auth b2AuthResp
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("b2 auth decode: %w", err)
	}

	client := &b2Client{
		apiURL:      auth.APIInfo.StorageAPI.APIURL,
		authToken:   auth.AuthorizationToken,
		downloadURL: auth.APIInfo.StorageAPI.DownloadURL,
		httpClient:  hc,
	}

	// Bucket-restricted application keys have allowed.bucketId pre-filled;
	// calling b2_list_buckets with such a key returns HTTP 400.
	if auth.Allowed.BucketID != "" {
		client.bucketID = auth.Allowed.BucketID
		return client, nil
	}

	// Resolve bucket name → bucket ID.
	bucketID, err := client.resolveBucketID(ctx, auth.AccountID, bucketName)
	if err != nil {
		return nil, fmt.Errorf("b2 resolve bucket: %w", err)
	}
	client.bucketID = bucketID
	return client, nil
}

func (c *b2Client) resolveBucketID(ctx context.Context, accountID, bucketName string) (string, error) {
	body := map[string]string{"bucketName": bucketName}
	if accountID != "" {
		body["accountId"] = accountID
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiURL+"/b2api/v3/b2_list_buckets", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", c.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("list_buckets HTTP %d", resp.StatusCode)
	}

	var lr b2ListBucketsResp
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", err
	}
	for _, b := range lr.Buckets {
		if b.BucketName == bucketName {
			return b.BucketID, nil
		}
	}
	return "", fmt.Errorf("bucket %q not found", bucketName)
}

// uploadFile uploads data to B2 and returns the file ID.
func (c *b2Client) uploadFile(ctx context.Context, fileName string, data []byte) (string, error) {
	// Step 1: get upload URL.
	body := map[string]string{"bucketId": c.bucketID}
	bodyData, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiURL+"/b2api/v3/b2_get_upload_url", bytes.NewReader(bodyData))
	if err != nil {
		return "", fmt.Errorf("get_upload_url request: %w", err)
	}
	req.Header.Set("Authorization", c.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get_upload_url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get_upload_url HTTP %d", resp.StatusCode)
	}

	var uu b2GetUploadURLResp
	if err := json.NewDecoder(resp.Body).Decode(&uu); err != nil {
		return "", fmt.Errorf("get_upload_url decode: %w", err)
	}

	// Step 2: upload.
	sha1sum := fmt.Sprintf("%x", sha1.Sum(data)) //nolint:gosec — B2 requires SHA-1
	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		uu.UploadURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("upload request: %w", err)
	}
	uploadReq.Header.Set("Authorization", uu.AuthorizationToken)
	uploadReq.Header.Set("X-Bz-File-Name", fileName)
	uploadReq.Header.Set("Content-Type", "application/octet-stream")
	uploadReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	uploadReq.Header.Set("X-Bz-Content-Sha1", sha1sum)

	uploadResp, err := c.httpClient.Do(uploadReq)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	defer uploadResp.Body.Close()
	if uploadResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(uploadResp.Body, 512))
		return "", fmt.Errorf("upload HTTP %d: %s", uploadResp.StatusCode, b)
	}

	var ur b2UploadResp
	if err := json.NewDecoder(uploadResp.Body).Decode(&ur); err != nil {
		return "", fmt.Errorf("upload decode: %w", err)
	}
	return ur.FileID, nil
}

// downloadFile downloads a file by ID. Returns the raw bytes.
func (c *b2Client) downloadFile(ctx context.Context, fileID string) ([]byte, error) {
	url := c.downloadURL + "/b2api/v3/b2_download_file_by_id?fileId=" + fileID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download request: %w", err)
	}
	req.Header.Set("Authorization", c.authToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("download HTTP %d: %s", resp.StatusCode, body)
	}

	return io.ReadAll(resp.Body)
}
