package todo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	core "github.com/very-amused/CSplan-API/core"
)

// List - A titled list of TodoItems
type List struct {
	ID        uint             `json:"-"`
	EncodedID string           `json:"id"`
	Title     string           `json:"title" validate:"required,base64,max=255"`
	Items     []Item           `json:"items" validate:"required,dive"`
	Meta      core.IndexedMeta `json:"meta" validate:"required"`
}

// SortableLists - A sortable array of todo lists
type SortableLists []List

func (lists SortableLists) Len() int {
	return len(lists)
}
func (lists SortableLists) Less(i, j int) bool {
	return lists[i].Meta.Index < lists[j].Meta.Index
}
func (lists SortableLists) Swap(i, j int) {
	// We know these values are not nil because a call to less with nil values will never return true and thus trigger a swap
	old1 := lists[i]
	old2 := lists[j]
	old1.Meta.Index = uint(j)
	old2.Meta.Index = uint(i)
	lists[j] = old1
	lists[i] = old2
}

// Item - A singular todo item belonging to a parent List
type Item struct {
	Title       string   `json:"title" validate:"required,base64"`
	Description string   `json:"description" validate:"required,base64"`
	Done        string   `json:"done"` // This is in reality a boolean, but it is an encrypted one, so we store it as a string
	Tags        []string `json:"tags" validate:"required,dive,base64"`
}

// Response - Response to creation or update of a todo list
type Response struct {
	EncodedID string            `json:"id"`
	Meta      core.IndexedState `json:"meta"`
}

// Patch - Patch to update a todolist
type Patch struct {
	Title *string           `json:"title,omitempty" validate:"omitempty,base64,max=255"`
	Items *[]Item           `json:"items,omitempty" validate:"omitempty,dive"`
	Meta  *IndexedMetaPatch `json:"meta,omitempty"`
}

// IndexedMetaPatch - Same as MetaPatch but with index
type IndexedMetaPatch struct {
	CryptoKey string `json:"cryptoKey,omitempty" validate:"omitempty,base64,max=700"`
	Index     *uint  `json:"index,omitempty" db:"_Index"`
}

// parseID - Parse a uint ID from a string representation
func parseID(strID string) (uint, error) {
	id, e := strconv.ParseUint(strID, 10, 0)
	return uint(id), e
}

// AddTodo - Add a todo list to the database
func AddTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var list List
	json.NewDecoder(r.Body).Decode(&list)
	if err := core.ValidateStruct(list); err != nil {
		core.WriteError(w, *err)
		return
	}
	user := ctx.Value(core.Key("user")).(uint)

	// Generate a unique ID
	var err error
	list.ID, err = core.MakeUniqueID("TodoLists")
	if err != nil {
		core.WriteError500(w, err)
	}
	list.EncodedID = core.EncodeID(list.ID)

	// Figure out list index
	var max, index uint
	err = core.DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		index = 0
	} else if max == 255 {
		core.WriteError(w, core.HTTPError{
			Title: "Resource Conflict",
			Message: `The max index allowed for todo-lists (255) has been exceeded.
			Remove one or more todo lists before attempting to add more`,
			Status: 409})
		return
	} else {
		index = max + 1
	}

	// Encode items as json
	for i, item := range list.Items {
		if len(item.Tags) == 0 {
			list.Items[i].Tags = make([]string, 0) // This is really dumb, golang json lib bad
			// For clarity, go's json lib will serialize any empty primitive array as null unless you check each it and manually call make with a value of 0
			// I don't know who thought this was a good idea, I don't know how this hasn't been patched yet, but this is really, really dumb
		}
	}
	m, err := json.Marshal(list.Items)
	encoded := string(m)

	_, err = core.DB.Exec("INSERT INTO TodoLists (ID, UserID, Title, Items, _Index, CryptoKey) VALUES (?, ?, FROM_BASE64(?), ?, ?, FROM_BASE64(?))",
		list.ID, user, list.Title, encoded, index, list.Meta.CryptoKey)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	// Get checksum
	var Checksum string
	err = core.DB.Get(&Checksum, "SELECT SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE ID = ?", list.ID)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(Response{
		EncodedID: core.EncodeID(list.ID),
		Meta: core.IndexedState{
			Index:    index,
			Checksum: Checksum}})
}

// GetTodos - Retrieve a slice of all todo lists belonging to a user
func GetTodos(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)

	var max int
	core.DB.Get(&max, "SELECT Max(_Index) FROM TodoLists WHERE UserID = ?", user)

	rows, err := core.DB.Query("SELECT ID, TO_BASE64(Title), Items, _Index, TO_BASE64(CryptoKey), SHA(CONCAT(Title, Items)) FROM TodoLists WHERE UserID = ?", user)
	defer rows.Close()
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	// A slice of slice pointers is used here as a solution to 2 problems
	// 1. If a single depth slice is used and there are index collisions in the db, then overwrites will occur and effectively render a list unaccessable
	// 2. If pointers are not used, then gaps in indexes (nil values in the parent slice) are unable to be checked for
	// This allows for lists to effectively be sorted in such a way that they later can be copied to a single-depth slice for encoding, while also
	// fixing index collisions/gaps in deferred SQL statements
	// This solution is much faster than simply appending and then implementing a sort algorithm
	var lists = make([]*[]List, max+1)

	for rows.Next() {
		var list List
		var encoded string
		err = rows.Scan(&list.ID, &list.Title, &encoded, &list.Meta.Index, &list.Meta.CryptoKey, &list.Meta.Checksum)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
		// json unmarshal list items
		json.Unmarshal([]byte(encoded), &list.Items)

		list.EncodedID = core.EncodeID(list.ID)
		i := list.Meta.Index
		// Append the list to the subslice at index i
		if lists[i] != nil {
			*lists[i] = append(*lists[i], list)
		} else {
			lists[i] = &[]List{list}
		}
	}

	// Validate and fix index collisions
	var final []List
	var k int
	for i := 0; i < len(lists); i++ {
		if lists[i] == nil {
			continue
		}

		for j := 0; j < len(*lists[i]); j++ {
			final = append(final, (*lists[i])[j])
			// Defer updating any inaccurate indexes in the db
			if final[k].Meta.Index != uint(k) {
				defer core.DB.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", k, final[k].ID)
			}
			k++
		}
		// Immediately free the memory occupied by this subslice
		lists[i] = nil
	}
	if len(final) == 0 {
		final = make([]List, 0)
	}

	json.NewEncoder(w).Encode(final)
}

// GetTodo - Retrieve a single todo list by id
func GetTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	var list List

	// Parse ID from url
	id, err := core.DecodeID(mux.Vars(r)["id"])
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
		return
	}
	list.ID = id

	// Select the todo list from the db
	var encoded string
	rows, err := core.DB.Query("SELECT TO_BASE64(Title) AS Title, Items, _Index, TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE ID = ? AND UserID = ?",
		list.ID, user)
	defer rows.Close()
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	// If rows.Next() returns false, it means no rows are found, which indicates a 404
	if rows.Next() {
		err = rows.Scan(&list.Title, &encoded, &list.Meta.Index, &list.Meta.CryptoKey, &list.Meta.Checksum)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
	} else {
		core.WriteError404(w)
		return
	}

	// json unmarshal list items
	err = json.Unmarshal([]byte(encoded), &list.Items)
	if err != nil {
		core.WriteError500(w, err)
		return
	}
	list.EncodedID = core.EncodeID(list.ID)

	json.NewEncoder(w).Encode(list)
}

// UpdateTodo - Update a todo list by id
func UpdateTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	id, err := core.DecodeID(mux.Vars(r)["id"])
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Bad Request",
			Message: "Malformed ID param",
			Status:  400})
		return
	}

	// Validate patch body
	var patch Patch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := core.ValidateStruct(patch); err != nil {
		core.WriteError(w, *err)
		return
	}

	// Existence + ownership check
	rows, _ := core.DB.Query("SELECT 1 FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)
	defer rows.Close()
	if !rows.Next() {
		core.WriteError404(w)
		return
	}

	// Patch only the fields specified in the request
	var updates []string
	var args []interface{}
	if patch.Title != nil {
		updates = append(updates, "Title = FROM_BASE64(?)")
		args = append(args, *patch.Title)
	}
	if patch.Items != nil {
		// Avoid being encoded as null
		if len(*patch.Items) == 0 {
			*patch.Items = make([]Item, 0)
		}
		m, _ := json.Marshal(patch.Items)
		encoded := string(m)
		updates = append(updates, "Items = ?")
		args = append(args, encoded)
	}
	if patch.Meta != nil && len(patch.Meta.CryptoKey) > 0 {
		updates = append(updates, "CryptoKey = FROM_BASE64(?)")
		args = append(args, patch.Meta.CryptoKey)
	}
	// Perform the patch as a single query
	if len(updates) > 0 {
		query := fmt.Sprintf("UPDATE TodoLists SET %s WHERE ID = ?", strings.Join(updates, ", "))
		args = append(args, id)
		_, err := core.DB.Exec(query, args...)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
	}

	// Get state information
	var state core.IndexedState
	err = core.DB.Get(&state, "SELECT SHA(CONCAT(Title, Items)) AS Checksum, _Index FROM TodoLists WHERE ID = ?", id)
	if err != nil {
		core.WriteError500(w, err)
		return
	}

	// If there's an index shift specified, perform it
	o := state.Index
	if patch.Meta != nil && (*patch.Meta).Index != nil && *(*patch.Meta).Index != o {
		n := *patch.Meta.Index
		// Initiate a transaction, so if any step fails, things are not left in a broken state
		tx, err := core.DB.Beginx()
		if err != nil {
			core.WriteError500(w, err)
			return
		}
		defer tx.Rollback()

		// Select a map of index -> id
		ids := make(map[uint]uint)
		rows, err := core.DB.Query("SELECT ID, _Index FROM TodoLists WHERE UserID = ?", user)
		defer rows.Close()
		if err != nil {
			core.WriteError500(w, err)
			return
		}
		for rows.Next() {
			var id, index uint
			rows.Scan(&id, &index)
			ids[index] = id
		}

		// Shift
		if n > o {
			// (o, n]
			for i := o + 1; i <= n; i++ {
				_, err = tx.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", i-1, ids[i])
				if err != nil {
					core.WriteError500(w, err)
					return
				}
			}
		} else if n < o {
			// [n, o)
			for i := n; i < o; i++ {
				_, err = tx.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", i+1, ids[i])
				if err != nil {
					core.WriteError500(w, err)
					return
				}
			}
		}
		// Update the index of the list itself
		_, err = tx.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", n, id)
		if err != nil {
			core.WriteError500(w, err)
			return
		}
		state.Index = n
		tx.Commit()
	}

	json.NewEncoder(w).Encode(Response{
		EncodedID: core.EncodeID(id),
		Meta:      state})
}

// DeleteTodo - Delete a todo list by ID
func DeleteTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(core.Key("user")).(uint)
	id, err := core.DecodeID(mux.Vars(r)["id"])
	if err != nil {
		core.WriteError(w, core.HTTPError{
			Title:   "Bad Request",
			Message: "Malformed or missing ID param",
			Status:  400})
		return
	}

	// Select useful information that will be used for updating indexes later
	var max, index uint
	core.DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	core.DB.Get(&index, "SELECT _Index FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)

	results, _ := core.DB.Exec("DELETE FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)
	if affected, _ := results.RowsAffected(); affected > 0 {
		// Update indexes to be accurate after the delete operation
		for i := index + 1; i <= max; i++ {
			core.DB.Exec("UPDATE TodoLists SET _Index = ? WHERE _Index = ? AND UserID = ?", i-1, i, user)
		}
	}

	w.WriteHeader(204)
}
