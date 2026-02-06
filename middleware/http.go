package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/rafaelsanzio/passcheck"
)

// DefaultHTTPExtractor extracts the password from an *http.Request by checking
// (1) JSON body for Content-Type application/json, and (2) form value.
// The request body is read once and restored so the next handler can read it.
// The password field name is taken from Config.PasswordField.
func DefaultHTTPExtractor(cfg Config) Extractor {
	return &httpExtractor{field: cfg.PasswordField}
}

type httpExtractor struct {
	field string
}

func (e *httpExtractor) ExtractPassword(req interface{}) (string, error) {
	r, ok := req.(*http.Request)
	if !ok {
		return "", nil
	}
	// Prefer JSON if Content-Type is application/json (e.g. application/json; charset=utf-8).
	if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Content-Type")), "application/json") {
		return e.extractJSON(r)
	}
	// Form (including multipart).
	return e.extractForm(r), nil
}

func (e *httpExtractor) extractForm(r *http.Request) string {
	return r.FormValue(e.field)
}

func (e *httpExtractor) extractJSON(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return "", err
	}
	// Restore body for the next handler.
	r.Body = io.NopCloser(bytes.NewReader(body))

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", err
	}
	if v, ok := raw[e.field]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}
	}
	return "", nil
}

// HTTP returns a net/http middleware that validates the request password
// using passcheck. If the password is missing (and SkipIfEmpty is false),
// or scores below MinScore, the middleware responds with 400 and does not
// call next. Otherwise it calls next.ServeHTTP.
//
// Password is extracted from the request using the default extractor
// (form value and JSON body; see [DefaultHTTPExtractor]). Use a custom
// [Config] to set PasswordField, MinScore, or [passcheck.Config].
func HTTP(cfg Config, next http.Handler) http.Handler {
	def := DefaultConfig()
	if cfg.PasswordField == "" {
		cfg.PasswordField = def.PasswordField
	}
	if cfg.MinScore == 0 {
		cfg.MinScore = def.MinScore
	}
	extractor := DefaultHTTPExtractor(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		password, err := extractor.ExtractPassword(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid request body", nil)
			return
		}
		if password == "" {
			if cfg.SkipIfEmpty {
				next.ServeHTTP(w, r)
				return
			}
			writeWeakPasswordResponse(w, r, cfg, 0, nil, "password is required")
			return
		}
		pc := cfg.PasscheckConfig
		if verr := pc.Validate(); verr != nil {
			pc = passcheck.DefaultConfig()
		}
		result, err := passcheck.CheckWithConfig(password, pc)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "configuration error", err)
			return
		}
		if result.Score < cfg.MinScore {
			if cfg.OnFailure != nil {
				_ = cfg.OnFailure(result.Issues)
			}
			writeWeakPasswordResponse(w, r, cfg, result.Score, result.Issues, "password does not meet strength requirements")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeWeakPasswordResponse sends a 400 JSON response with score and issues.
func writeWeakPasswordResponse(w http.ResponseWriter, _ *http.Request, _ Config, score int, issues []passcheck.Issue, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	body := weakPasswordBody{Error: message, Score: score, Issues: issues}
	_ = json.NewEncoder(w).Encode(body)
}

// writeError sends a JSON error response and logs the cause if non-nil.
func writeError(w http.ResponseWriter, _ *http.Request, status int, message string, _ error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

type weakPasswordBody struct {
	Error  string            `json:"error"`
	Score  int               `json:"score"`
	Issues []passcheck.Issue `json:"issues"`
}
