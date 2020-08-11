package routes

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// Tag - A tag used to group together multiple items
type Tag struct {
	ID        uint    `json:"-"`
	EncodedID string  `json:"id"`
	Name      string  `json:"name" validate:"required,base64,max=255"`
	Color     string  `json:"color" validate:"required,base64,max=255"`
	Meta      TagMeta `json:"meta" validate:"required"`
}

// TagMeta - CryptoKey and checksum for tag creation
type TagMeta struct {
	CryptoKey string `json:"cryptoKey" validate:"required,base64,max=255"`
	Checksum  string `json:"checksum"`
}

// TagState - Checksum for tag create/update responses
type TagState struct {
	Checksum string `json:"checksum"`
}

// TagResponse - EncodedID and meta for responses to create/update operations
type TagResponse struct {
	EncodedID string   `json:"id"`
	Meta      TagState `json:"meta"`
}

// TagMetaPatch - Patch for tag meta + checksum
type TagMetaPatch struct {
	CryptoKey string `json:"cryptoKey" validate:"omitempty,base64,max=255"`
	Checksum  string `json:"checksum"`
}

// TagPatch - The body of a patch request for a tag
type TagPatch struct {
	ID        uint         `json:"-"`
	EncodedID string       `json:"id"`
	Name      string       `json:"name" validate:"omitempty,base64,max=255"`
	Color     string       `json:"color" validate:"omitempty,base64,max=255"`
	Meta      TagMetaPatch `json:"meta"`
}

// AddTag - Create a new tag
func AddTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var tag Tag
	json.NewDecoder(r.Body).Decode(&tag)
	if err := HTTPValidate(w, tag); err != nil {
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
				HTTPInternalServerError(w, err)
				return
			}
			tag.ID++
		}
	}

	// Add to db
	_, err := DB.Exec("INSERT INTO Tags (ID, UserID, Name, Color, CryptoKey) VALUES (?, ?, FROM_BASE64(?), FROM_BASE64(?), FROM_BASE64(?))", tag.ID, user, tag.Name, tag.Color, tag.Meta.CryptoKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Get tag checksum
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE ID = ?", tag.ID)

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(TagResponse{
		EncodedID: EncodeID(tag.ID),
		Meta: TagState{
			Checksum: checksum}})
}

// GetTags - Retrieve a list of all of a user's tags
func GetTags(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	tags := make([]Tag, 0)

	rows, err := DB.Query("SELECT ID, TO_BASE64(Name) AS Name, TO_BASE64(Color) AS Color, TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE UserID = ?", user)
	defer rows.Close()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Create the tags list by iterating through the result set
	for rows.Next() {
		var tag Tag
		err := rows.Scan(&tag.ID, &tag.Name, &tag.Color, &tag.Meta.CryptoKey, &tag.Meta.Checksum)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
		tag.EncodedID = EncodeID(tag.ID)
		tags = append(tags, tag)
	}

	json.NewEncoder(w).Encode(tags)
}

// GetTag - Retrieve a tag by ID
func GetTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var tag Tag
	tag.EncodedID = mux.Vars(r)["id"]
	var err error
	tag.ID, err = DecodeID(tag.EncodedID)
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
	}

	rows, err := DB.Query("SELECT TO_BASE64(Name), TO_BASE64(Color), TO_BASE64(CryptoKey), SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE UserID = ? AND ID = ?", user, tag.ID)
	defer rows.Close()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	if rows.Next() {
		rows.Scan(&tag.Name, &tag.Color, &tag.Meta.CryptoKey, &tag.Meta.Checksum)
	} else {
		HTTPNotFoundError(w)
		return
	}

	json.NewEncoder(w).Encode(tag)
}

// UpdateTag - Update a tag's name, color, and/or cryptokey
func UpdateTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var patch TagPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
		return
	}

	// Check if the referenced tag exists
	rows, err := DB.Query("SELECT 1 FROM Tags WHERE ID = ? AND UserID = ?", id, user)
	defer rows.Close()
	if !rows.Next() {
		HTTPNotFoundError(w)
		return
	} else if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Update only the specified fields
	if len(patch.Name) > 0 {
		_, err = DB.Exec("UPDATE Tags SET Name = FROM_BASE64(?) WHERE ID = ?", patch.Name, id)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}
	if len(patch.Color) > 0 {
		_, err = DB.Exec("UPDATE Tags SET Color = FROM_BASE64(?) WHERE ID = ?", patch.Color, id)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}
	if len(patch.Meta.CryptoKey) > 0 {
		_, err = DB.Exec("UPDATE Tags SET CryptoKey = FROM_BASE64(?) WHERE ID = ?", patch.Meta.CryptoKey, id)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}

	// Select the new checksum
	var checksum string
	DB.Get(&checksum, "SELECT SHA(CONCAT(Name, Color, CryptoKey)) FROM Tags WHERE ID = ?", id)

	json.NewEncoder(w).Encode(TagResponse{
		EncodedID: EncodeID(id),
		Meta: TagState{
			Checksum: checksum}})
}

// DeleteTag - Delete a tag by ID
func DeleteTag(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
		return
	}

	DB.Exec("DELETE FROM Tags WHERE ID = ? AND UserID = ?", id, user)
	w.WriteHeader(204)
}
