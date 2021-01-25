package todo

import (
	"context"
	"encoding/json"
	"net/http"

	core "github.com/very-amused/CSplan-API/core"
)

// NoList - A specific form of todo list designed to hold any items that do not belong to a parent list
type NoList struct {
	Items []Item    `json:"items" validate:"dive"`
	Meta  core.Meta `json:"meta"`
}

// NoListPatch - A patch to an existing nolist collection
type NoListPatch struct {
	Items *[]Item         `json:"items,omitempty" validate:"omitempty,dive"`
	Meta  *core.MetaPatch `json:"meta,omitempty"`
}

// CreateNoList - The creation of a nolist collection should be automatically accomplished at register-time,
// but a route is specified here as a manual failsafe (no body POST)
// TODO: allow post body for this route
func CreateNoList(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var list NoList
	json.NewDecoder(r.Body).Decode(&list)
	if err := core.ValidateStruct(list); err != nil {
		core.WriteError(w, *err)
		return
	}

	// Check for resource conflicts
	rows, err := core.DB.Query("SELECT 1 FROM NoList WHERE UserID = ?", user)
	defer rows.Close()
	if rows.Next() {
		core.WriteError(w, core.HTTPError{
			Title:   "Resource Conflict",
			Message: "This user already has a no list collection created.",
			Status:  409})
		return
	} else if err != nil {
		core.WriteError500(w, err)
		return
	}

	// Marshal list items
	marshalled, _ := json.Marshal(list.Items)
	encoded := string(marshalled)

	_, err = core.DB.Exec("INSERT INTO NoList (UserID, Items, CryptoKey) VALUES (?, ?, FROM_BASE64(?))", user, encoded, list.Meta.CryptoKey)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	var Checksum string
	core.DB.Get(&Checksum, "SELECT SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)

	w.Header().Set("Location", "/nolist")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(core.StateResponse{
		Meta: core.State{
			Checksum: Checksum}})
}

// UpdateNoList - Update the items or key of a nolist collection
func UpdateNoList(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var patch NoListPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := core.ValidateStruct(patch); err != nil {
		core.WriteError(w, *err)
		return
	}

	// Update the collection's items (if included in the request)
	if patch.Items != nil {
		marshalled, _ := json.Marshal(patch.Items)
		_, err := core.DB.Exec("UPDATE NoList SET Items = ? WHERE UserID = ?", marshalled, user)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
	}
	if patch.Meta != nil && patch.Meta.CryptoKey != nil {
		_, err := core.DB.Exec("UPDATE NoList SET CryptoKey = FROM_BASE64(?) WHERE UserID = ?", *patch.Meta.CryptoKey, user)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
	}

	// Retrieve the updated checksum
	var checksum string
	core.DB.Get(&checksum, "SELECT SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)

	json.NewEncoder(w).Encode(core.StateResponse{
		Meta: core.State{
			Checksum: checksum}})
}

// GetNoList - Retrieve a nolist collection
func GetNoList(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var nolist NoList

	rows, err := core.DB.Query("SELECT Items, TO_BASE64(CryptoKey), SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)
	defer rows.Close()
	if !rows.Next() {
		core.WriteError404(w)
		return
	} else if err != nil {
		core.WriteError500(w, err)
		return
	}
	var encoded string
	rows.Scan(&encoded, &nolist.Meta.CryptoKey, &nolist.Meta.Checksum)
	err = json.Unmarshal([]byte(encoded), &nolist.Items)
	if err != nil {
		core.WriteError500(w, err)
	}

	json.NewEncoder(w).Encode(nolist)
}
