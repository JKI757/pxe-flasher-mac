package httpd

import (
	"net/http"
	"os"
	"time"

	"netboot-flasher/pkg/sessions"
)

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/manifest", s.handleManifest)
	mux.HandleFunc("/done", s.handleDone)
	mux.HandleFunc("/", s.handleFile)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.manifestJSON)
}

func (s *Server) handleDone(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	mac := r.URL.Query().Get("mac")
	details := map[string]string{
		"status": status,
	}
	if mac != "" {
		details["mac"] = mac
	}
	if s.sessions != nil {
		_ = s.sessions.Append(sessions.SessionEvent{
			Type:    sessions.EventImageDone,
			MAC:     mac,
			Time:    time.Now().UTC(),
			Details: details,
		})
	}
	if s.logger != nil {
		s.logger.Infof("/done status=%s mac=%s", status, mac)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ack"))
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	absPath, ok := s.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(absPath)
	if err != nil {
		http.Error(w, "file open failed", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.Error(w, "file stat failed", http.StatusInternalServerError)
		return
	}
	if s.sessions != nil {
		_ = s.sessions.Append(sessions.SessionEvent{
			Type: sessions.EventHTTPGet,
			Time: time.Now().UTC(),
			Details: map[string]string{
				"path": r.URL.Path,
			},
		})
	}
	if s.logger != nil {
		s.logger.Infof("http %s %s", r.Method, r.URL.Path)
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}
