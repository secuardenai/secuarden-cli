package webui

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	db        *storage.DB
	version   string
	static    http.Handler
	indexHTML []byte
}

type overview struct {
	Version     string                 `json:"version"`
	GeneratedAt string                 `json:"generated_at"`
	Summary     *storage.StatusSummary `json:"summary"`
}

func New(db *storage.DB, version string) *Server {
	staticFS, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	index, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		panic(err)
	}
	return &Server{db: db, version: version, static: http.FileServer(http.FS(staticFS)), indexHTML: index}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/sessions/{id}", s.session)
	mux.HandleFunc("GET /", s.index)
	return securityHeaders(mux)
}

func (s *Server) overview(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	summary, err := s.db.GetStatusSummary(dayStart, dayStart.AddDate(0, 0, 1), 50)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, overview{Version: s.version, GeneratedAt: now.UTC().Format(time.RFC3339), Summary: summary})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 1000 {
			writeError(w, errors.New("limit must be between 1 and 1000"), http.StatusBadRequest)
			return
		}
		limit = value
	}
	result, err := s.db.QueryEvents(storage.EventFilter{
		Limit:      limit,
		ActionType: r.URL.Query().Get("action"),
		SessionID:  r.URL.Query().Get("session"),
		Sensitive:  r.URL.Query().Get("sensitive") == "true",
	})
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	result, err := s.db.GetSessionInvestigation(r.PathValue("id"))
	if err != nil {
		writeError(w, errors.New("session not found"), http.StatusNotFound)
		return
	}
	writeJSON(w, result)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/assets/") {
		notFound(w, r)
		return
	}
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(s.indexHTML)
		return
	}
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/assets")
	s.static.ServeHTTP(w, r)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, errors.New("not found"), http.StatusNotFound)
}
