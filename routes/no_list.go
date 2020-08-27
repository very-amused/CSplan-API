package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// NoList - A specific form of todo list designed to hold any items that do not belong to a parent list
type NoList struct {
	Items []TodoItem `json:"items" validate:"dive"`
	Meta  Meta       `json:"meta"`
}

// NoListPatch - A patch to an existing nolist collection
type NoListPatch struct {
	Items []TodoItem `json:"items" validate:"dive"`
	Meta  MetaPatch  `json:"meta"`
}

// CreateNoList - The creation of a nolist collection should be automatically accomplished at register-time,
// but a route is specified here as a manual failsafe (no body POST)
// TODO: allow post body for this route
func CreateNoList(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var list NoList
	json.NewDecoder(r.Body).Decode(&list)
	if err := HTTPValidate(w, list); err != nil {
		return
	}

	// Check for resource conflicts
	rows, err := DB.Query("SELECT 1 FROM NoList WHERE UserID = ?", user)
	defer rows.Close()
	if rows.Next() {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "This user already has a no list collection created.",
			Status:  409})
		return
	} else if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Marshal list items
	marshalled, _ := json.Marshal(list.Items)
	encoded := string(marshalled)

	_, err = DB.Exec("INSERT INTO NoList (UserID, Items, CryptoKey) VALUES (?, ?, FROM_BASE64(?))", user, encoded, list.Meta.CryptoKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	var Checksum string
	DB.Get(&Checksum, "SELECT SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)

	w.Header().Set("Location", "/nolist")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum}})
}

// UpdateNoList - Update the items or key of a nolist collection
func UpdateNoList(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var patch NoListPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	// Marshal the items sent
	marshalled, err := json.Marshal(patch.Items)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	encoded := string(marshalled)

	// Update the collection's items (if included in the request)
	if len(patch.Items) > 0 {
		_, err = DB.Exec("UPDATE NoList SET Items = ? WHERE UserID = ?", encoded, user)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}
	if len(patch.Meta.CryptoKey) > 0 {
		_, err = DB.Exec("UPDATE NoList SET CryptoKey = FROM_BASE64(?) WHERE UserID = ?", patch.Meta.CryptoKey, user)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}

	// Retrieve the updated checksum
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)

	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum: checksum}})
}

// GetNoList - Retrieve a nolist collection
func GetNoList(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var nolist NoList

	rows, err := DB.Query("SELECT Items, TO_BASE64(CryptoKey), SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)
	defer rows.Close()
	if !rows.Next() {
		HTTPNotFoundError(w)
		return
	} else if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	var encoded string
	rows.Scan(&encoded, &nolist.Meta.CryptoKey, &nolist.Meta.Checksum)
	err = json.Unmarshal([]byte(encoded), &nolist.Items)
	if err != nil {
		HTTPInternalServerError(w, err)
	}

	json.NewEncoder(w).Encode(nolist)
}
