package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var twoWeeks int = 60 * 60 * 24 * 14

var authError Error = Error{
	Title:   "Unauthorized",
	Message: "Missing or invalid authorization token(s)",
	Status:  401}

// Authenticate - Authorize and identify a user for a authenticate route.
func Authenticate(w http.ResponseWriter, r *http.Request) (id uint, e error) {
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
	parsedID, err := strconv.ParseUint(strings.Split(token.Value, ":")[1], 10, 0)
	if err != nil {
		HTTPError(w, authError)
		return 0, authError
	}
	id = uint(parsedID)

	rows, err := DB.Queryx("SELECT Token, CSRFtoken FROM Tokens WHERE UserID = ?", id)
	defer rows.Close()
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

// Login - Bypass the challenge authentication system, and simply return either a 409 or a token for the account
// associated with the email sent
func Login(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if !AuthBypass {
		HTTPError(w, Error{
			Title:   "Unauthorized",
			Message: "Invalid authorization route requested. An authorization challenge must be requested and submitted.",
			Status:  401})
		return
	}

	var user User
	json.NewDecoder(r.Body).Decode(&user)
	if !user.exists() {
		HTTPNotFoundError(w)
		return
	}

	// Select the user's ID based on their email
	DB.Get(&user, "SELECT ID FROM Users WHERE Email = ?", user.Email)

	tokens, err := user.newTokens()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.Header().Set("Set-Cookie", fmt.Sprintf("Authorization=%s; Max-Age=%d; HttpOnly", tokens.Token, twoWeeks))
	// Don't write the HttpOnly token to the JSON response, this token must be kept from javascript access
	json.NewEncoder(w).Encode(map[string]string{
		"CSRFtoken": tokens.CSRFtoken})
}
