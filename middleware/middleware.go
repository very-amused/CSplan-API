package middleware

import (
	"net/http"

	"github.com/very-amused/CSplan-API/routes"
)

// SetContentType - Set both incoming and outcoming content type to application/json
func SetContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept", "application/json")
		w.Header().Set("Content-Type", "application/json")
		if len(r.Header.Get("Content-Type")) > 0 && r.Header.Get("Content-Type") != "application/json" {
			routes.HTTPError(w, routes.Error{
				Title:   "Unsupported Media Type",
				Message: "Expected content type is \"application/json\"",
				Status:  415})
			return
		}
		next.ServeHTTP(w, r)
	})
}

var allowedOrigins = [2]string{"http://localhost:3030", "https://csplan.co"}

// CORS - Handle cross-origin resource access
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}
