package routes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
)

// TodoList - A titled list of TodoItems
type TodoList struct {
	ID    uint        `json:"id"`
	Title string      `json:"title" validate:"max=255,base64"`
	Items []TodoItem  `json:"items" validate:"required,dive"`
	Meta  IndexedMeta `json:"meta" validate:"required"`
}

// TodoItem - A singular todo item belonging to a parent TodoList
type TodoItem struct {
	Title       string `json:"title" validate:"base64"`
	Description string `json:"description" validate:"base64"`
	Category    string `json:"category" validate:"omitempty,base64"`
}

// IndexedMeta - Full meta for all encrypted fields with order
type IndexedMeta struct {
	CryptoKey string `json:"cryptoKey" validate:"base64"`
	Checksum  string `json:"checksum"`
	Index     uint   `json:"index"`
}

// IndexedState - Partial meta (checksum) for all encrypted fields of a resource with order
type IndexedState struct {
	Checksum string `json:"checksum"`
	Index    uint   `json:"index"`
}

// TodoResponse - Response to creation or update of a todo list
type TodoResponse struct {
	ID   uint         `json:"id"`
	Meta IndexedState `json:"meta"`
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
	err = tx.Get(&exists, "SELECT 1 FROM TodoLists WHERE ID = ?", list.ID)
	for err == nil {
		list.ID++
		err = tx.Get(&exists, "SELECT 1 FROM TodoLists WHERE ID = ?", list.ID)
	}

	// Figure out list index
	var max uint
	err = tx.Get(&max, "SELECT MAX(_Index) FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	} else if max == 255 {
		HTTPError(w, Error{
			Title: "Resource Conflict",
			Message: `The max index allowed for todo-lists (255) has been exceeded.
			Remove one or more todo lists before attempting to add more`,
			Status: 409})
		return
	}
	index := max + 1

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
		HTTPInternalServerError(w, err)
		return
	}
	rows, err := tx.Query("SELECT ID, TO_BASE64(Title) AS Title, Items, _Index, TO_BASE64(CryptoKey) AS CryptoKey FROM TodoLists WHERE UserID = ?", user)
	if err != nil {
		HTTPInternalServerError(w, err)
		return
	}
	lists := make([]TodoList, max+1)

	for rows.Next() {
		var list TodoList
		var encoded string
		err = rows.Scan(&list.ID, &list.Title, &encoded, &list.Meta.Index, &list.Meta.CryptoKey)
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
