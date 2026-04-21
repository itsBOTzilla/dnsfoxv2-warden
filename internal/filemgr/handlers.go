// handlers.go — gRPC / Connect-Go handlers for the v2 file manager.
//
// Every handler:
//   1. Maps req.site_id → site_<first-15-chars> username via provisioning.SiteUsername.
//   2. LookupSite to resolve the user's uid/gid and docroot.
//   3. Delegates to the filemgr.Site methods for the actual FS work.
//   4. Returns the proto response (or a Connect error with a proper code).
package filemgr

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"path/filepath"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// Handler groups the six gRPC file-manager RPCs.
type Handler struct{}

// NewHandler returns an empty handler (no deps — all state lives per-request).
func NewHandler() *Handler { return &Handler{} }

func (Handler) resolve(siteID string) (*Site, error) {
	if siteID == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("site_id is required"))
	}
	username := provisioning.SiteUsername(siteID)
	site, err := LookupSite(username)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return site, nil
}

// mapErr converts filemgr errors to Connect errors with appropriate codes.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrPathTraversal):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, ErrTooLarge):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, ErrNotEmpty):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// ListFiles implements WardenService.ListFiles.
func (h *Handler) ListFiles(_ context.Context, req *connect.Request[wardenv1.ListFilesRequest]) (*connect.Response[wardenv1.ListFilesResponse], error) {
	site, err := h.resolve(req.Msg.GetSiteId())
	if err != nil {
		return nil, err
	}
	entries, err := site.List(req.Msg.GetPath())
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]*wardenv1.FileEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, &wardenv1.FileEntry{
			Name:      e.Name,
			IsDir:     e.IsDir,
			SizeBytes: e.Size,
			ModTime:   timestamppb.New(e.ModTime),
			Mode:      e.Mode,
		})
	}
	return connect.NewResponse(&wardenv1.ListFilesResponse{Entries: out}), nil
}

// ReadFile implements WardenService.ReadFile.
func (h *Handler) ReadFile(_ context.Context, req *connect.Request[wardenv1.ReadFileRequest]) (*connect.Response[wardenv1.ReadFileResponse], error) {
	site, err := h.resolve(req.Msg.GetSiteId())
	if err != nil {
		return nil, err
	}
	buf, info, err := site.Read(req.Msg.GetPath())
	if err != nil {
		return nil, mapErr(err)
	}
	mt := mime.TypeByExtension(filepath.Ext(req.Msg.GetPath()))
	if mt == "" {
		mt = http.DetectContentType(buf)
	}
	return connect.NewResponse(&wardenv1.ReadFileResponse{
		Content:   buf,
		MimeType:  mt,
		SizeBytes: info.Size(),
	}), nil
}

// WriteFile implements WardenService.WriteFile.
func (h *Handler) WriteFile(_ context.Context, req *connect.Request[wardenv1.WriteFileRequest]) (*connect.Response[wardenv1.WriteFileResponse], error) {
	site, err := h.resolve(req.Msg.GetSiteId())
	if err != nil {
		return nil, err
	}
	if err := site.Write(req.Msg.GetPath(), req.Msg.GetContent(), req.Msg.GetMode()); err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&wardenv1.WriteFileResponse{
		BytesWritten: int64(len(req.Msg.GetContent())),
	}), nil
}

// DeleteFile implements WardenService.DeleteFile.
func (h *Handler) DeleteFile(_ context.Context, req *connect.Request[wardenv1.DeleteFileRequest]) (*connect.Response[wardenv1.DeleteFileResponse], error) {
	site, err := h.resolve(req.Msg.GetSiteId())
	if err != nil {
		return nil, err
	}
	if err := site.Delete(req.Msg.GetPath(), req.Msg.GetRecursive()); err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&wardenv1.DeleteFileResponse{Deleted: true}), nil
}

// CreateDirectory implements WardenService.CreateDirectory.
func (h *Handler) CreateDirectory(_ context.Context, req *connect.Request[wardenv1.CreateDirectoryRequest]) (*connect.Response[wardenv1.CreateDirectoryResponse], error) {
	site, err := h.resolve(req.Msg.GetSiteId())
	if err != nil {
		return nil, err
	}
	if err := site.Mkdir(req.Msg.GetPath(), req.Msg.GetMode()); err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&wardenv1.CreateDirectoryResponse{Created: true}), nil
}

// MoveFile implements WardenService.MoveFile.
func (h *Handler) MoveFile(_ context.Context, req *connect.Request[wardenv1.MoveFileRequest]) (*connect.Response[wardenv1.MoveFileResponse], error) {
	site, err := h.resolve(req.Msg.GetSiteId())
	if err != nil {
		return nil, err
	}
	if err := site.Move(req.Msg.GetFromPath(), req.Msg.GetToPath()); err != nil {
		return nil, mapErr(err)
	}
	return connect.NewResponse(&wardenv1.MoveFileResponse{Moved: true}), nil
}
