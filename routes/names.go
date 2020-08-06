package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// Name - Names for a user
type Name struct {
	FirstName string `json:"firstname" validate:"max=255,omitempty,base64"`
	LastName  string `json:"lastname" validate:"max=255,omitempty,base64"`
	Username  string `json:"username" validate:"max=255,omitempty,base64"`
	Meta      Meta   `json:"meta" validate:"required"`
}

// Meta - Full meta for all encrypted fields of a resource
type Meta struct {
	CryptoKey string `json:"cryptoKey" validate:"base64"`
	Checksum  string `json:"checksum"`
}

// NamePatch - Same as Names, except without required cryptokey
type NamePatch struct {
	FirstName string    `json:"firstname" validate:"max=255,omitempty,base64"`
	LastName  string    `json:"lastname" validate:"max=255,omitempty,base64"`
	Username  string    `json:"username" validate:"max=255,omitempty,base64"`
	Meta      MetaPatch `json:"meta"`
}

// MetaPatch - Patch to update a resource's meta
type MetaPatch struct {
	CryptoKey string `json:"cryptoKey" validate:"omitempty,base64"`
}

// MetaResponse - Response to creation or update of a name
type MetaResponse struct {
	Meta State `json:"meta"`
}

// State - Partial meta (checksum) for all encrypted fields of a resource
// Used for responses to post/patch reqs
type State struct {
	Checksum string `json:"checksum"`
}

// AddName - Add a user's name
func AddName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var name Name
	json.NewDecoder(r.Body).Decode(&name)
	if err := HTTPValidate(w, name); err != nil {
		return
	}
	user := ctx.Value(key("user")).(uint)

	// Existence check
	var exists int
	err := DB.Get(&exists, "SELECT 1 FROM Names WHERE UserID = ?", user)
	if err == nil {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "Name already created for this user. PATCH:/name for updates",
			Status:  409})
		return
	}

	_, err = DB.Exec("INSERT INTO Names (UserID, FirstName, LastName, Username, CryptoKey) VALUES (?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))",
		user, name.FirstName, name.LastName, name.Username, name.Meta.CryptoKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Select checksum for encrypted fields
	var Checksum string
	err = DB.Get(&Checksum, "SELECT SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum}})
}

// GetName - Retrieve a user's name
func GetName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)

	var name Name
	err := DB.Get(&name, "SELECT TO_BASE64(FirstName) AS FirstName, TO_BASE64(LastName) AS LastName, TO_BASE64(Username) AS Username FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested name was not found",
			Status:  404})
		return
	}

	// Refuse to return a resource without its associated cryptokey
	err = DB.Get(&name.Meta, "SELECT TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil || len(name.Meta.CryptoKey) == 0 {
		_, err = DB.Exec("DELETE FROM Names WHERE UserID = ?", user)
		if err != nil {
			HTTPInternalServerError(w, err)
		}
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested name was not found",
			Status:  404})
		return
	}

	json.NewEncoder(w).Encode(name)
}

// UpdateName - Update a user's name
func UpdateName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var patch NamePatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	user := ctx.Value(key("user")).(uint)
	// Existence check
	var exists int
	err := DB.Get(&exists, "SELECT 1 FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPNotFoundError(w)
		return
	}

	// Only patch the fields that aren't empty
	errs := make([]error, 4)
	if len(patch.FirstName) > 0 {
		_, err = DB.Exec("UPDATE Names SET FirstName = FROM_BASE64(?) WHERE UserID = ?", patch.FirstName, user)
		errs = append(errs, err)
	}
	if len(patch.LastName) > 0 {
		_, err = DB.Exec("UPDATE Names SET LastName = FROM_BASE64(?) WHERE UserID = ?", patch.LastName, user)
		errs = append(errs, err)
	}
	if len(patch.Username) > 0 {
		_, err = DB.Exec("UPDATE Names SET Username = FROM_BASE64(?) WHERE UserID = ?", patch.Username, user)
		errs = append(errs, err)
	}
	if len(patch.Meta.CryptoKey) > 0 {
		_, err = DB.Exec("UPDATE Names SET CryptoKey = FROM_BASE64(?) WHERE UserID = ?", patch.Meta.CryptoKey, user)
		errs = append(errs, err)
	}
	for _, err = range errs {
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}

	var Checksum string
	err = DB.Get(&Checksum, "SELECT SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum}})
}

// DeleteName - Delete a user's name
func DeleteName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)

	DB.Exec("DELETE FROM Names WHERE UserID = ?", user)
	w.WriteHeader(204)
}
