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
		if r.Header.Get("Content-Type") != "application/json" {
			routes.HTTPError(w, routes.Error{
				Title:   "Unsupported Media Type",
				Message: "Expected content type is \"application/json\"",
				Status:  415})
			return
		}
		next.ServeHTTP(w, r)
	})
}
