package routes

import (
	"context"
	"encoding/json"
	"net/http"
)

// NoListCreate - The creation of a nolist collection should be automatically accomplished at register-time,
// but a route is specified here as a manual failsafe (no body POST)
func NoListCreate(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)

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

	_, err = DB.Exec("INSERT INTO NoList (UserID) VALUES (?)", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	w.WriteHeader(204)
}

/// Key operations for the user's nolist collection are handled separately,
/// due to the lack of specificity of which request to add items a key would be bundled with

// NoListAddKey - Add a cryptokey to a nolist collection
func NoListAddKey(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var meta Meta
	json.NewDecoder(r.Body).Decode(&meta)
	if err := HTTPValidate(w, meta); err != nil {
		return
	}

	// Check for resource conflicts
	var key string
	DB.Get(&key, "SELECT CryptoKey FROM NoList WHERE UserID = ?", user)
	if len(key) > 0 {
		HTTPError(w, Error{
			Title:   "Resource Conflict",
			Message: "This no list collection already has a key set. To update this key use PATCH:/nolist/key, to delete this key use DELETE:/nolist/key.",
			Status:  409})
		return
	}

	// Set the user's nolist cryptokey and retrieve the checksum
	DB.Exec("UPDATE NoList SET CryptoKey = FROM_BASE64(?) WHERE UserID = ?", meta.CryptoKey, user)
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum: checksum}})
}

// NoListUpdateKey - Update the cryptokey associated with a nolist collection
func NoListUpdateKey(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var meta Meta
	json.NewDecoder(r.Body).Decode(&meta)
	if err := HTTPValidate(w, meta); err != nil {
		return
	}

	// Check for resource conflicts
	var key string
	DB.Get(&key, "SELECT CryptoKey FROM NoList WHERE UserID = ?", user)
	if len(key) == 0 {
		HTTPNotFoundError(w)
		return
	}

	// Update the user's nolist cryptokey and retrieve the checksum
	DB.Exec("UPDATE NoList SET CryptoKey = FROM_BASE64(?) WHERE UserID = ?", meta.CryptoKey, user)
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Items, CryptoKey)) FROM NoList WHERE UserID = ?", user)

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(MetaResponse{
		Meta: State{
			Checksum: checksum}})
}
