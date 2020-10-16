package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// TodoList - A titled list of TodoItems
type TodoList struct {
	ID        uint        `json:"-"`
	EncodedID string      `json:"id"`
	Title     string      `json:"title" validate:"required,base64,max=255"`
	Items     []TodoItem  `json:"items" validate:"required,dive"`
	Meta      IndexedMeta `json:"meta" validate:"required"`
}

// TodoItem - A singular todo item belonging to a parent TodoList
type TodoItem struct {
	Title       string   `json:"title" validate:"required,base64"`
	Description string   `json:"description" validate:"required,base64"`
	Done        string   `json:"done"` // This is in reality a boolean, but it is an encrypted one, so we store it as a string
	Tags        []string `json:"tags" validate:"dive,base64"`
}

// IndexedMeta - Full meta for all encrypted fields with order
type IndexedMeta struct {
	CryptoKey string `json:"cryptoKey" validate:"required,base64,max=700"`
	Checksum  string `json:"checksum"`
	Index     uint   `json:"index" db:"_Index"`
}

// IndexedState - Partial meta (checksum) for all encrypted fields of a resource with order
type IndexedState struct {
	Checksum string `json:"checksum"`
	Index    uint   `json:"index" db:"_Index"`
}

// TodoResponse - Response to creation or update of a todo list
type TodoResponse struct {
	EncodedID string       `json:"id"`
	Meta      IndexedState `json:"meta"`
}

// TodoPatch - Patch to update a todolist
type TodoPatch struct {
	Title string           `json:"title" validate:"omitempty,base64,max=255"`
	Items []TodoItem       `json:"items" validate:"dive"`
	Meta  IndexedMetaPatch `json:"meta"`
}

// IndexedMetaPatch - Same as MetaPatch but with index
type IndexedMetaPatch struct {
	CryptoKey string `json:"cryptoKey" validate:"omitempty,base64,max=700"`
	Index     uint   `json:"index" db:"_Index"`
}

// parseID - Parse a uint ID from a string representation
func parseID(strID string) (uint, error) {
	id, e := strconv.ParseUint(strID, 10, 0)
	return uint(id), e
}

// AddTodo - Add a todo list to the database
func AddTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var list TodoList
	json.NewDecoder(r.Body).Decode(&list)
	if err := HTTPValidate(w, list); err != nil {
		return
	}
	user := ctx.Value(key("user")).(uint)

	// Generate a random 20 digit id
	list.ID = MakeID()

	// Enusre the list's ID's uniqueness
	var exists int
	for true {
		err := DB.Get(&exists, "SELECT 1 FROM TodoLists WHERE ID = ?", list.ID)
		if err != nil {
			break
		}
		list.ID++
	}

	// Figure out list index
	var max, index uint
	err := DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		index = 0
	} else if max == 255 {
		HTTPError(w, Error{
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

	_, err = DB.Exec("INSERT INTO TodoLists (ID, UserID, Title, Items, _Index, CryptoKey) VALUES (?, ?, FROM_BASE64(?), ?, ?, FROM_BASE64(?))",
		list.ID, user, list.Title, encoded, index, list.Meta.CryptoKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Get checksum
	var Checksum string
	err = DB.Get(&Checksum, "SELECT SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE ID = ?", list.ID)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(TodoResponse{
		EncodedID: EncodeID(list.ID),
		Meta: IndexedState{
			Index:    index,
			Checksum: Checksum}})
}

// GetTodos - Retrieve a slice of all todo lists belonging to a user
func GetTodos(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)

	var max uint
	err := DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		json.NewEncoder(w).Encode(make([]TodoList, 0))
		return
	}
	rows, err := DB.Query("SELECT ID, TO_BASE64(Title) AS Title, Items, _Index, TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE UserID = ?", user)
	defer rows.Close()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	lists := make([]TodoList, max+1)

	for rows.Next() {
		var list TodoList
		var encoded string
		err = rows.Scan(&list.ID, &list.Title, &encoded, &list.Meta.Index, &list.Meta.CryptoKey, &list.Meta.Checksum)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
		// json unmarshal list items
		err = json.Unmarshal([]byte(encoded), &list.Items)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		lists[list.Meta.Index] = list
		lists[list.Meta.Index].EncodedID = EncodeID(list.ID)
	}

	json.NewEncoder(w).Encode(lists)
}

// GetTodo - Retrieve a single todo list by id
func GetTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	var list TodoList

	// Parse ID from url
	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed id param",
			Status:  400})
		return
	}
	list.ID = id

	// Select the todo list from the db
	var encoded string
	rows, err := DB.Query("SELECT TO_BASE64(Title) AS Title, Items, _Index, TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE ID = ? AND UserID = ?",
		list.ID, user)
	defer rows.Close()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	// If rows.Next() returns false, it means no rows are found, which indicates a 404
	if rows.Next() {
		err = rows.Scan(&list.Title, &encoded, &list.Meta.Index, &list.Meta.CryptoKey, &list.Meta.Checksum)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	} else {
		HTTPNotFoundError(w)
		return
	}

	// json unmarshal list items
	err = json.Unmarshal([]byte(encoded), &list.Items)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	list.EncodedID = EncodeID(list.ID)

	json.NewEncoder(w).Encode(list)
}

// UpdateTodo - Update a todo list by id
func UpdateTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed ID param",
			Status:  400})
		return
	}

	// Validate patch body
	var patch TodoPatch
	json.NewDecoder(r.Body).Decode(&patch)
	if err := HTTPValidate(w, patch); err != nil {
		return
	}

	// Existence + ownership check
	rows, _ := DB.Query("SELECT 1 FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)
	defer rows.Close()
	if !rows.Next() {
		HTTPNotFoundError(w)
		return
	}

	// Patch only the fields specified in the request
	var updates []string
	var args []interface{}
	if len(patch.Title) > 0 {
		updates = append(updates, "Title = FROM_BASE64(?)")
		args = append(args, patch.Title)
	}
	if patch.Items != nil {
		// Avoid being encoded as null
		if len(patch.Items) == 0 {
			patch.Items = make([]TodoItem, 0)
		}
		m, _ := json.Marshal(patch.Items)
		encoded := string(m)
		updates = append(updates, "Items = ?")
		args = append(args, encoded)
	}
	if len(patch.Meta.CryptoKey) > 0 {
		updates = append(updates, "CryptoKey = FROM_BASE64(?)")
		args = append(args, patch.Meta.CryptoKey)
	}
	// Perform the patch as a single query
	if len(updates) > 0 {
		query := fmt.Sprintf("UPDATE TodoLists SET %s WHERE ID = ?", strings.Join(updates, ", "))
		args = append(args, id)
		_, err := DB.Exec(query, args...)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}

	// Get state information
	var state IndexedState
	err = DB.Get(&state, "SELECT SHA(CONCAT(Title, Items)) AS Checksum, _Index FROM TodoLists WHERE ID = ?", id)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// If there's an index shift specified, perform it
	n := patch.Meta.Index
	o := state.Index
	if n != o {
		// Create an array of ids for all todos belonging to the user
		var max int
		err = DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		// Copy
		todos := make([]uint, max+1)
		for i := 0; i <= max; i++ {
			err = DB.Get(&todos[i], "SELECT ID FROM TodoLists WHERE _Index = ?", i)
			if err != nil {
				HTTPInternalServerError(w, err)
				return
			}
		}

		// Substitute
		_, err = DB.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", n, todos[o])
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		// Shift
		if n > o {
			// (o, n]
			for i := o + 1; i <= n; i++ {
				_, err = DB.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", i-1, todos[i])
				if err != nil {
					HTTPInternalServerError(w, err)
					return
				}
			}
		} else if n < o {
			// (n, o]
			for i := n; i < o; i++ {
				_, err = DB.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", i+1, todos[i])
				if err != nil {
					HTTPInternalServerError(w, err)
					return
				}
			}
		}
		state.Index = n
	}

	json.NewEncoder(w).Encode(TodoResponse{
		EncodedID: EncodeID(id),
		Meta:      state})
}

// DeleteTodo - Delete a todo list by ID
func DeleteTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(uint)
	id, err := DecodeID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed or missing ID param",
			Status:  400})
		return
	}

	// Select useful information that will be used for updating indexes later
	var max, index uint
	DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	DB.Get(&index, "SELECT _Index FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)

	results, _ := DB.Exec("DELETE FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)
	if affected, _ := results.RowsAffected(); affected > 0 {
		// Update indexes to be accurate after the delete operation
		for i := index + 1; i <= max; i++ {
			DB.Exec("UPDATE TodoLists SET _Index = ? WHERE _Index = ? AND UserID = ?", i-1, i, user)
		}
	}

	w.WriteHeader(204)
}
