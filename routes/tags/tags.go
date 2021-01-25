package tags

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	. "github.com/very-amused/CSplan-API/core"
)

// Tag - A tag used to group together multiple items
type Tag struct {
	ID        uint   `json:"-"`
	EncodedID string `json:"id"`
	Name      string `json:"name" validate:"required,base64,max=255"`
	Color     string `json:"color" validate:"required,base64,max=255"`
	Meta      Meta   `json:"meta" validate:"required"`
}

// Response - EncodedID and meta for responses to create/update operations
type Response struct {
	EncodedID string `json:"id"`
	Meta      State  `json:"meta"`
}

// Patch - The body of a patch request for a tag
type Patch struct {
	ID        uint       `json:"-"`
	EncodedID string     `json:"id"`
	Name      *string    `json:"name,omitempty" validate:"omitempty,base64,max=255"`
	Color     *string    `json:"color,omitempty" validate:"omitempty,base64,max=255"`
	Meta      *MetaPatch `json:"meta,omitempty"`
}

// AddTag - Create a new tag
func AddTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(Key("user")).(uint)
	var tag Tag
	json.NewDecoder(r.Body).Decode(&tag)
	if err := ValidateStruct(tag); err != nil {
		WriteError(w, *err)
		return
	}

	tag.ID = MakeID()
	// Validate tag ID's uniqueness
	for {
		rows, err := DB.Query("SELECT 1 FROM Tags WHERE ID = ?", tag.ID)
		defer rows.Close()
		if !rows.Next() {
			break
		} else {
			if err != nil {
				WriteError500(w, err)
				return
			}
			tag.ID++
		}
	}

	// Add to db
	_, err := DB.Exec("INSERT INTO Tags (ID, UserID, Name, Color, CryptoKey) VALUES (?, ?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))", tag.ID, user, tag.Name, tag.Color, tag.Meta.CryptoKey)
	if err != nil {
		WriteError500(w, err)
		return
	}

	// Get tag checksum
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE ID = ?", tag.ID)

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(Response{
		EncodedID: EncodeID(tag.ID),
		Meta: State{
			Checksum: checksum}})
}

// GetTags - Retrieve a list of all of a user's tags
func GetTags(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(Key("user")).(uint)
	tags := make([]Tag, 0)

	rows, err := DB.Query("SELECT ID, TO_BASE64(Name) AS Name, TO_BASE64(Color) AS Color, TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE UserID = ?", user)
	defer rows.Close()
	if err != nil {
		WriteError500(w, err)
		return
	}

	// Create the tags list by iterating through the result set
	for rows.Next() {
		var tag Tag
		err := rows.Scan(&tag.ID, &tag.Name, &tag.Color, &tag.Meta.CryptoKey, &tag.Meta.Checksum)
		if err != nil {
			WriteError500(w, err)
			return
		}
		tag.EncodedID = EncodeID(tag.ID)
		tags = append(tags, tag)
	}

	json.NewEncoder(w).Encode(tags)
}

// GetTag - Retrieve a tag by ID
func GetTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(Key("user")).(uint)
	var tag Tag
	tag.EncodedID = mux.Vars(r)["id"]
	var err error
	tag.ID, err = DecodeID(tag.EncodedID)
	if err != nil {
		WriteError(w, HTTPError{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
	}

	rows, err := DB.Query("SELECT TO_BASE64(Name), TO_BASE64(Color), TO_BASE64(CryptoKey), SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE UserID = ? AND ID = ?", user, tag.ID)
	defer rows.Close()
	if err != nil {
		WriteError500(w, err)
		return
	}

	if rows.Next() {
		rows.Scan(&tag.Name, &tag.Color, &tag.Meta.CryptoKey, &tag.Meta.Checksum)
	} else {
		WriteError404(w)
		return
	}

	json.NewEncoder(w).Encode(tag)
}

// UpdateTag - Update a tag's name, color, and/or cryptokey
func UpdateTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(Key("user")).(uint)
	var patch Patch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := ValidateStruct(patch); err != nil {
		WriteError(w, *err)
		return
	}

	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		WriteError(w, HTTPError{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
		return
	}

	// Check if the referenced tag exists
	rows, err := DB.Query("SELECT 1 FROM Tags WHERE ID = ? AND UserID = ?", id, user)
	defer rows.Close()
	if !rows.Next() {
		WriteError404(w)
		return
	} else if err != nil {
		WriteError500(w, err)
		return
	}

	// Update only the specified fields
	if patch.Name != nil {
		_, err = DB.Exec("UPDATE Tags SET Name = FROM_BASE64(?) WHERE ID = ?", patch.Name, id)
		if err != nil {
			WriteError500(w, err)
			return
		}
	}
	if patch.Color != nil {
		_, err = DB.Exec("UPDATE Tags SET Color = FROM_BASE64(?) WHERE ID = ?", patch.Color, id)
		if err != nil {
			WriteError500(w, err)
			return
		}
	}
	if patch.Meta != nil && patch.Meta.CryptoKey != nil {
		_, err = DB.Exec("UPDATE Tags SET CryptoKey = FROM_BASE64(?) WHERE ID = ?", *patch.Meta.CryptoKey, id)
		if err != nil {
			WriteError500(w, err)
			return
		}
	}

	// Select the new checksum
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE ID = ?", id)

	json.NewEncoder(w).Encode(Response{
		EncodedID: EncodeID(id),
		Meta: State{
			Checksum: checksum}})
}

// DeleteTag - Delete a tag by ID
func DeleteTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(Key("user")).(uint)
	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		WriteError(w, HTTPError{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
		return
	}

	DB.Exec("DELETE FROM Tags WHERE ID = ? AND UserID = ?", id, user)
	w.WriteHeader(204)
}
