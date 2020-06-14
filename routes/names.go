package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// Name - Names for a user
type Name struct {
	FirstName string   `json:"firstname" validate:"max=255"`
	LastName  string   `json:"lastname" validate:"max=255"`
	Username  string   `json:"username" validate:"max=255"`
	Meta      NameMeta `json:"meta" validate:"required"`
}

// NamePatch - Same as Names, except without required cryptokey
type NamePatch struct {
	FirstName string `json:"firstname" validate:"max=255"`
	LastName  string `json:"lastname" validate:"max=255"`
	Username  string `json:"username" validate:"max=255"`
}

// NameMeta - Full meta for all encrypted fields of names
type NameMeta struct {
	CryptoKey string `json:"cryptoKey" validate:"required"`
	Checksum  string `json:"checksum"`
}

// NameResponse - Response to creation or update of a name
type NameResponse struct {
	Meta NameState `json:"meta"`
}

// NameState - Partial meta (checksum) for all encrypted fields of names
// Used for responses to post/patch reqs
type NameState struct {
	Checksum string `json:"checksum"`
}

// AddName - Add a user's name
func AddName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var name Name
	json.NewDecoder(r.Body).Decode(&name)
	if err := HTTPValidate(w, name); err != nil {
		return
	}
	user := ctx.Value(key("user")).(int)

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	defer tx.Rollback()

	// Existence check
	var exists int
	err = tx.Get(&exists, "SELECT 1 FROM Names WHERE UserID = ?", user)
	if err == nil {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "Name already created for this user. PATCH:/name for updates",
			Status:  409})
		return
	}

	_, err = tx.Exec("INSERT INTO Names (UserID, FirstName, LastName, Username, CryptoKey) VALUES (?, ?, ?, ?, ?)",
		user, name.FirstName, name.LastName, name.Username, name.Meta.CryptoKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Select checksum for encrypted fields
	var Checksum string
	err = tx.Get(&Checksum, "SELECT SHA(CONCAT(FirstName, LastName, Username)) AS checksum FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	tx.Commit()

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(NameResponse{
		Meta: NameState{
			Checksum}})
}

// GetName - Retrieve a user's name
func GetName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(int)

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
	}
	defer tx.Rollback()

	var name Name
	err = tx.Get(&name, "SELECT FirstName, LastName, Username FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Not Found",
			Message: "The requested name was not found",
			Status:  404})
		return
	}

	// Refuse to return a resource without its associated cryptokey
	err = tx.Get(&name.Meta, "SELECT CryptoKey, SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
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
	tx.Commit()

	json.NewEncoder(w).Encode(name)
}

// UpdateName - Update a user's name
func UpdateName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var patch NamePatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	user := ctx.Value(key("user")).(int)

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	defer tx.Rollback()

	// Only patch the fields that aren't empty
	if len(patch.FirstName) > 0 {
		_, err = tx.Exec("UPDATE Names SET FirstName = ? WHERE UserID = ?", patch.FirstName, user)
	}
	if len(patch.LastName) > 0 {
		_, err = tx.Exec("UPDATE  SET LastName = ? WHERE UserID = ?", patch.LastName, user)
	}
	if len(patch.Username) > 0 {
		_, err = tx.Exec("UPDATE  SET Username = ? WHERE UserID = ?", patch.Username, user)
	}
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	var Checksum string
	err = tx.Get(&Checksum, "SELECT SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	tx.Commit()

	json.NewEncoder(w).Encode(NameResponse{
		Meta: NameState{
			Checksum}})
}

// DeleteName - Delete a user's name
func DeleteName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(int)

	DB.Exec("DELETE FROM Names WHERE UserID = ?", user)
	w.WriteHeader(204)
}
