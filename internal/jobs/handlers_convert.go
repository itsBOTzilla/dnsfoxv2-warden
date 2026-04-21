// handlers_convert.go — v1 Docker → v2 cgroup conversion handler.
// Dispatched from executor.go on JOB_TYPE_CONVERT_V1_TO_V2.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/v1convert"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// handleConvertV1ToV2 runs the v1convert package against a Node.js or
// WordPress site identified by the payload. Only nodejs is implemented
// today; other app types return FAILED with a clear message.
//
// Payload keys:
//   site_id    (uuid, required)
//   domain     (string, required)
//   app_type   ("nodejs" | "wordpress" | "php", required)
//   plan       (string, optional; defaults to "fox")
//   reuse_port (bool, optional; default true — keeps existing v1 nginx vhost)
func (e *Executor) handleConvertV1ToV2(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	siteID, _ := payload["site_id"].(string)
	domain, _ := payload["domain"].(string)
	appType, _ := payload["app_type"].(string)
	plan, _ := payload["plan"].(string)
	reusePort := true
	if v, ok := payload["reuse_port"].(bool); ok {
		reusePort = v
	}

	if siteID == "" || domain == "" || appType == "" {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			"missing site_id / domain / app_type"
	}

	switch appType {
	case "nodejs":
		conv := v1convert.New()
		res, err := conv.ConvertNodejsSite(ctx, v1convert.NodejsRequest{
			SiteID:    siteID,
			Domain:    domain,
			Plan:      plan,
			ReusePort: reusePort,
		})
		if err != nil {
			log.Printf("[jobs] convert_v1_to_v2 site=%s err=%v", siteID, err)
			return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
		}
		blob, _ := json.Marshal(res)
		log.Printf("[jobs] convert_v1_to_v2 site=%s done port=%d downtime_ms=%d",
			siteID, res.Port, res.DowntimeMs)
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, string(blob)

	case "wordpress", "php":
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("v1convert for app_type=%s not yet implemented", appType)

	default:
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("unknown app_type: %q", appType)
	}
}
