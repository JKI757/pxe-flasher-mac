package httpd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"netboot-flasher/pkg/logging"
	"netboot-flasher/pkg/profiles"
	"netboot-flasher/pkg/sessions"
)

type Config struct {
	BindAddr string
	Manifest *profiles.Manifest
	Sessions *sessions.Store
	Logger   *logging.Logger
}

type Server struct {
	server       *http.Server
	files        map[string]string
	manifestJSON []byte
	sessions     *sessions.Store
	logger       *logging.Logger
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Manifest == nil {
		return nil, fmt.Errorf("manifest required")
	}
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("bind address required")
	}
	manifestJSON, err := json.MarshalIndent(cfg.Manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	files := make(map[string]string)
	for _, file := range cfg.Manifest.Files {
		if file.Kind != "http" {
			continue
		}
		files[file.ServePath] = file.AbsPath
	}
	mux := http.NewServeMux()
	s := &Server{
		server: &http.Server{
			Addr:              cfg.BindAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
		files:        files,
		manifestJSON: manifestJSON,
		sessions:     cfg.Sessions,
		logger:       cfg.Logger,
	}
	s.registerRoutes(mux)
	return s, nil
}

func (s *Server) ListenAndServe() error {
	if s == nil || s.server == nil {
		return fmt.Errorf("server not initialized")
	}
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(timeout time.Duration) error {
	if s == nil || s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.server.Shutdown(ctx)
}
