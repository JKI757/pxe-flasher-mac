package tftpd

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/pin/tftp"

	"netboot-flasher/pkg/logging"
	"netboot-flasher/pkg/profiles"
	"netboot-flasher/pkg/sessions"
)

type Config struct {
	BindAddr string
	Manifest *profiles.Manifest
	Logger   *logging.Logger
	Sessions *sessions.Store
}

type Server struct {
	bindAddr string
	server   *tftp.Server
	files    map[string]string
	logger   *logging.Logger
	sessions *sessions.Store
	stats    Stats
}

type Stats struct {
	Requests uint64
	Bytes    uint64
	Errors   uint64
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.BindAddr == "" {
		return nil, fmt.Errorf("bind address required")
	}
	if cfg.Manifest == nil {
		return nil, fmt.Errorf("manifest required")
	}
	files := make(map[string]string)
	for _, file := range cfg.Manifest.Files {
		if file.Kind != "tftp" {
			continue
		}
		key := strings.TrimPrefix(file.ServePath, "/")
		if key == "" {
			continue
		}
		files[key] = file.AbsPath
	}
	s := &Server{
		bindAddr: cfg.BindAddr,
		files:    files,
		logger:   cfg.Logger,
		sessions: cfg.Sessions,
	}
	s.server = tftp.NewServer(s.handleRead, s.handleWrite)
	return s, nil
}

func (s *Server) ListenAndServe() error {
	if s == nil || s.server == nil {
		return fmt.Errorf("tftp server not initialized")
	}
	return s.server.ListenAndServe(s.bindAddr)
}

func (s *Server) Shutdown() {
	if s == nil || s.server == nil {
		return
	}
	s.server.Shutdown()
}

func (s *Server) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{
		Requests: atomic.LoadUint64(&s.stats.Requests),
		Bytes:    atomic.LoadUint64(&s.stats.Bytes),
		Errors:   atomic.LoadUint64(&s.stats.Errors),
	}
}

func (s *Server) handleRead(filename string, rf io.ReaderFrom) error {
	atomic.AddUint64(&s.stats.Requests, 1)
	clean, err := sanitizeFilename(filename)
	if err != nil {
		atomic.AddUint64(&s.stats.Errors, 1)
		return err
	}
	absPath, ok := s.files[clean]
	if !ok {
		atomic.AddUint64(&s.stats.Errors, 1)
		return fmt.Errorf("file not found")
	}
	file, err := os.Open(absPath)
	if err != nil {
		atomic.AddUint64(&s.stats.Errors, 1)
		return err
	}
	defer file.Close()
	if s.logger != nil {
		s.logger.Infof("tftp read %s", clean)
	}
	if s.sessions != nil {
		_ = s.sessions.Append(sessions.SessionEvent{
			Type: sessions.EventTFTPRead,
			Details: map[string]string{
				"file": clean,
			},
		})
	}
	n, err := rf.ReadFrom(file)
	if err != nil {
		atomic.AddUint64(&s.stats.Errors, 1)
		return err
	}
	atomic.AddUint64(&s.stats.Bytes, uint64(n))
	return nil
}

func (s *Server) handleWrite(_ string, _ io.WriterTo) error {
	atomic.AddUint64(&s.stats.Requests, 1)
	atomic.AddUint64(&s.stats.Errors, 1)
	return fmt.Errorf("write requests not supported")
}

func sanitizeFilename(filename string) (string, error) {
	filename = strings.TrimSpace(filename)
	filename = strings.TrimPrefix(filename, "/")
	if filename == "" {
		return "", fmt.Errorf("empty filename")
	}
	if strings.Contains(filename, "\\") {
		return "", fmt.Errorf("invalid path separator")
	}
	clean := path.Clean("/" + filename)
	clean = strings.TrimPrefix(clean, "/")
	if clean == "." || clean == "" {
		return "", fmt.Errorf("invalid filename")
	}
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("path traversal")
	}
	return clean, nil
}
