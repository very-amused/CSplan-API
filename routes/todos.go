package routes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// TodoList - A titled list of TodoItems
type TodoList struct {
	ID    uint        `json:"id"`
	Title string      `json:"title" validate:"required,base64,max=255"`
	Items []TodoItem  `json:"items" validate:"required,dive"`
	Meta  IndexedMeta `json:"meta" validate:"required"`
}

// TodoItem - A singular todo item belonging to a parent TodoList
type TodoItem struct {
	Title       string `json:"title" validate:"required,base64"`
	Description string `json:"description" validate:"required,base64"`
	Category    string `json:"category" validate:"omitempty,base64"`
}

// IndexedMeta - Full meta for all encrypted fields with order
type IndexedMeta struct {
	CryptoKey string `json:"cryptoKey" validate:"required,base64"`
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
	ID   uint         `json:"id"`
	Meta IndexedState `json:"meta"`
}

// TodoPatch - Patch to update a todolist
type TodoPatch struct {
	Title string           `json:"title" validate:"omitempty,base64,max=255"`
	Items []TodoItem       `json:"items" validate:"dive"`
	Meta  IndexedMetaPatch `json:"meta"`
}

// IndexedMetaPatch - Same as MetaPatch but with index
type IndexedMetaPatch struct {
	CryptoKey string `json:"cryptoKey" validate:"omitempty,base64"`
	Index     uint   `json:"index" db:"_Index"`
}

// TodoList.makeID - Make list.ID as a 20-digit unsigned integer
func (list *TodoList) makeID() error {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		return err
	}

	id := uint(binary.BigEndian.Uint64(bytes))
	for math.Ceil(math.Log10(float64(id))) < 20 {
		_, err := rand.Read(bytes)
		if err != nil {
			return err
		}

		id += uint(binary.BigEndian.Uint64(bytes))
	}
	list.ID = id
	return nil
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
	user := ctx.Value(key("user")).(int)
	if err := list.makeID(); err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	defer tx.Rollback()

	// Enusre the list's ID's uniqueness
	var exists int
	for true {
		err := tx.Get(&exists, "SELECT 1 FROM TodoLists WHERE ID = ?", list.ID)
		if err != nil {
			break
		}
		list.ID++
	}

	// Figure out list index
	var max, index uint
	err = tx.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
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
	m, err := json.Marshal(list.Items)
	encoded := string(m)

	_, err = tx.Exec("INSERT INTO TodoLists (ID, UserID, Title, Items, _Index, CryptoKey) VALUES (?, ?, FROM_BASE64(?), ?, ?, FROM_BASE64(?))",
		list.ID, user, list.Title, encoded, index, list.Meta.CryptoKey)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}

	// Get checksum
	var Checksum string
	err = tx.Get(&Checksum, "SELECT SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	tx.Commit()

	json.NewEncoder(w).Encode(TodoResponse{
		ID: list.ID,
		Meta: IndexedState{
			Index:    index,
			Checksum: Checksum}})
}

// GetTodos - Retrieve a slice of all todo lists belonging to a user
func GetTodos(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(int)

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	defer tx.Rollback()

	var max uint
	err = tx.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		w.WriteHeader(204)
		return
	}
	rows, err := tx.Query("SELECT ID, TO_BASE64(Title) AS Title, Items, _Index, TO_BASE64(CryptoKey) AS CryptoKey, SHA(CONCAT(Title, Items)) AS Checksum FROM TodoLists WHERE UserID = ?", user)
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
	}
	tx.Commit()

	json.NewEncoder(w).Encode(lists)
}

// GetTodo - Retrieve a single todo list by id
func GetTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(int)
	var list TodoList

	// Parse ID from url
	id, err := parseID(mux.Vars(r)["r"])
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

	json.NewEncoder(w).Encode(list)
}

// UpdateTodo - Update a todo list by id
func UpdateTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(int)
	id, err := parseID(mux.Vars(r)["id"])
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

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	defer tx.Rollback()

	// Existence + ownership check
	var exists int
	err = tx.Get(&exists, "SELECT 1 FROM TodoLists WHERE ID = ? AND UserID = ?",
		id, user)
	if err != nil {
		HTTPNotFoundError(w)
		return
	}

	// Patch only the fields specified in the request
	errs := make([]error, 4)
	if len(patch.Title) > 0 {
		_, err = tx.Exec("UPDATE TodoLists SET Title = FROM_BASE64(?) WHERE ID = ?", patch.Title, id)
		errs = append(errs, err)
	}
	if patch.Items != nil {
		m, err := json.Marshal(patch.Items)
		encoded := string(m)
		if err != nil {
			return
		}
		errs = append(errs, err)
		_, err = tx.Exec("UPDATE TodoLists SET Items = ? WHERE ID = ?", encoded, id)
		errs = append(errs, err)
	}
	if len(patch.Meta.CryptoKey) > 0 {
		_, err = tx.Exec("UPDATE TodoLists SET CryptoKey = FROM_BASE64(?) WHERE ID = ?", patch.Meta.CryptoKey, id)
		errs = append(errs, err)
	}
	// Handle any errors encountered during the patch
	for _, err := range errs {
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}
	}

	// Get state information
	var state IndexedState
	err = tx.Get(&state, "SELECT SHA(CONCAT(Title, Items)) AS Checksum, _Index FROM TodoLists WHERE ID = ?", id)
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
		err = tx.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		// Copy
		todos := make([]uint, max+1)
		for i := 0; i <= max; i++ {
			err = tx.Get(&todos[i], "SELECT ID FROM TodoLists WHERE _Index = ?", i)
			if err != nil {
				HTTPInternalServerError(w, err)
				return
			}
		}

		// Substitute
		_, err = tx.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", n, todos[o])
		if err != nil {
			HTTPInternalServerError(w, err)
			return
		}

		// Shift
		if n > o {
			// (o, n]
			for i := o + 1; i <= n; i++ {
				_, err = tx.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", i-1, todos[i])
				if err != nil {
					HTTPInternalServerError(w, err)
					return
				}
			}
		} else if n < o {
			// (n, o]
			for i := n + 1; i <= o; i++ {
				_, err = tx.Exec("UPDATE TodoLists SET _Index = ? WHERE ID = ?", i, todos[i-1])
				if err != nil {
					HTTPInternalServerError(w, err)
					return
				}
			}
		}
		state.Index = n
	}
	tx.Commit()

	json.NewEncoder(w).Encode(TodoResponse{
		ID:   id,
		Meta: state})
}

// DeleteTodo - Delete a todo list by ID
func DeleteTodo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value(key("user")).(int)
	id, err := parseID(mux.Vars(r)["id"])
	if err != nil {
		HTTPError(w, Error{
			Title:   "Bad Request",
			Message: "Malformed ID param",
			Status:  400})
		return
	}

	tx, err := DB.Beginx()
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	defer tx.Rollback()

	// Select useful information that will be used for updating indexes later
	var max, index uint
	DB.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	DB.Get(&index, "SELECT _Index FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)

	results, _ := tx.Exec("DELETE FROM TodoLists WHERE ID = ? AND UserID = ?", id, user)
	if affected, _ := results.RowsAffected(); affected > 0 {
		// Update indexes to be accurate after the delete operation
		for i := index + 1; i <= max; i++ {
			tx.Exec("UPDATE TodoLists SET _Index = ? WHERE _Index = ? AND UserID = ?", i-1, i, user)
		}
	}
	tx.Commit()

	w.WriteHeader(204)
}
