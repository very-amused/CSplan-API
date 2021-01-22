package profile

import (
	"context"
	"encoding/json"
	"net/http"

	core "github.com/very-amused/CSplan-API/core"
)

// Name - Names for a user
type Name struct {
	FirstName string    `json:"firstname" validate:"omitempty,base64,max=255"`
	LastName  string    `json:"lastname" validate:"max=255,omitempty,base64,max=255"`
	Username  string    `json:"username" validate:"max=255,omitempty,base64,max=255"`
	Meta      core.Meta `json:"meta" validate:"required"`
}

// NamePatch - Same as Names, except without required cryptokey
type NamePatch struct {
	FirstName string    `json:"firstname" validate:"omitempty,base64,max=255"`
	LastName  string    `json:"lastname" validate:"omitempty,base64,max=255"`
	Username  string    `json:"username" validate:"omitempty,base64,max=255"`
	Meta      MetaPatch `json:"meta"`
}

// MetaPatch - Patch to update a resource's meta
type MetaPatch struct {
	CryptoKey string `json:"cryptoKey" validate:"omitempty,base64,max=700"`
	Checksum  string `json:"checksum"`
}

// MetaResponse - Response to creation or update of a resource where only state is the appropriate response
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
	if err := core.ValidateStruct(name); err != nil {
		core.WriteError(w, *err)
		return
	}
	user := ctx.Value(core.Key("user")).(uint)

	// Existence check
	var exists int
	err := core.DB.Get(&exists, "SELECT 1 FROM Names WHERE UserID = ?", user)
	if err == nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Resource Conflict",
			Message: "Name already created for this user. PATCH:/name for updates",
			Status:  409})
		return
	}

	_, err = core.DB.Exec("INSERT INTO Names (UserID, FirstName, LastName, Username, CryptoKey) VALUES (?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))",
		user, name.FirstName, name.LastName, name.Username, name.Meta.CryptoKey)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	// Select checksum for encrypted fields
	var Checksum string
	err = core.DB.Get(&Checksum, "SELECT SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum}})
}

// GetName - Retrieve a user's name
func GetName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)

	var name Name
	err := core.DB.Get(&name, "SELECT TO_BASE64(FirstName) AS FirstName, TO_BASE64(LastName) AS LastName, TO_BASE64(Username) AS Username FROM Names WHERE UserID = ?", user)
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Not Found",
			Message: "The requested name was not found",
			Status:  404})
		return
	}

	// Refuse to return a resource without its associated cryptokey
	err = core.DB.Get(&name.Meta, "SELECT TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil || len(name.Meta.CryptoKey) == 0 {
		_, err = core.DB.Exec("DELETE FROM Names WHERE UserID = ?", user)
		if err != nil {
			core.WriteError500(w, err)
		}
		core.WriteError(w, core.HTTPError{
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
	if err := core.ValidateStruct(patch); err != nil {
		core.WriteError(w, *err)
		return
	}

	user := ctx.Value(core.Key("user")).(uint)
	// Existence check
	var exists int
	err := core.DB.Get(&exists, "SELECT 1 FROM Names WHERE UserID = ?", user)
	if err != nil {
		core.WriteError404(w)
		return
	}

	// Only patch the fields that aren't empty
	errs := make([]error, 4)
	if len(patch.FirstName) > 0 {
		_, err = core.DB.Exec("UPDATE Names SET FirstName = FROM_BASE64(?) WHERE UserID = ?", patch.FirstName, user)
		errs = append(errs, err)
	}
	if len(patch.LastName) > 0 {
		_, err = core.DB.Exec("UPDATE Names SET LastName = FROM_BASE64(?) WHERE UserID = ?", patch.LastName, user)
		errs = append(errs, err)
	}
	if len(patch.Username) > 0 {
		_, err = core.DB.Exec("UPDATE Names SET Username = FROM_BASE64(?) WHERE UserID = ?", patch.Username, user)
		errs = append(errs, err)
	}
	if len(patch.Meta.CryptoKey) > 0 {
		_, err = core.DB.Exec("UPDATE Names SET CryptoKey = FROM_BASE64(?) WHERE UserID = ?", patch.Meta.CryptoKey, user)
		errs = append(errs, err)
	}
	for _, err = range errs {
		if err != nil {
			core.WriteError500(w, err)
			return
		}
	}

	var Checksum string
	err = core.DB.Get(&Checksum, "SELECT SHA(CONCAT(FirstName, LastName, Username)) AS Checksum FROM Names WHERE UserID = ?", user)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum}})
}

// DeleteName - Delete a user's name
func DeleteName(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)

	core.DB.Exec("DELETE FROM Names WHERE UserID = ?", user)
	w.WriteHeader(204)
}
