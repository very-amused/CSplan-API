package routes

import (
	"net/http"
	"strings"
)

var authError Error = Error{
	Title:   "Unauthorized",
	Message: "Missing or invalid authorization token(s)",
	Status:  401}

// Authenticate - Authorize and identify a user for a authenticate route.
func Authenticate(w http.ResponseWriter, r *http.Request) (id string, e error) {
	token, err := r.Cookie("Authorization")
	if err != nil {
		HTTPError(w, authError)
		return "", authError
	}
	csrftoken := r.Header.Get("CRSF-Token")
	if len(csrftoken) == 0 {
		HTTPError(w, authError)
		return "", authError
	}

	// Parse user id from auth token
	id = strings.Split(token.Value, ":")[1]

	rows, err := DB.Queryx("SELECT Token, CSRFtoken FROM Tokens WHERE UserID = ?", id)
	if err != nil {
		HTTPInternalServerError(w, err)
		return "", err
	}
	for rows.Next() {
		var t Tokens
		rows.StructScan(&t)
		if t.Token == token.Value && t.CSRFtoken == csrftoken {
			return id, nil
		}
	}
	HTTPError(w, authError)
	return "", authError
}
