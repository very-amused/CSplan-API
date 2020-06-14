package routes

import (
	"net/http"
	"strconv"
	"strings"
)

var authError Error = Error{
	Title:   "Unauthorized",
	Message: "Missing or invalid authorization token(s)",
	Status:  401}

// Authenticate - Authorize and identify a user for a authenticate route.
func Authenticate(w http.ResponseWriter, r *http.Request) (id int, e error) {
	token, err := r.Cookie("Authorization")
	if err != nil {
		HTTPError(w, authError)
		return 0, authError
	}
	csrftoken := r.Header.Get("CSRF-Token")
	if len(csrftoken) == 0 {
		HTTPError(w, authError)
		return 0, authError
	}

	// Parse user id from auth token
	id, err = strconv.Atoi(strings.Split(token.Value, ":")[1])
	if err != nil {
		HTTPError(w, authError)
		return 0, authError
	}

	rows, err := DB.Queryx("SELECT Token, CSRFtoken FROM Tokens WHERE UserID = ?", id)
	if err != nil {
		HTTPInternalServerError(w, err)
		return 0, err
	}
	for rows.Next() {
		var t Tokens
		rows.StructScan(&t)
		if t.Token == token.Value && t.CSRFtoken == csrftoken {
			return id, nil
		}
	}
	HTTPError(w, authError)
	return 0, authError
}
