package routes

import (
	"context"
	"net/http"
)

// Route - Information to handle HTTP routes
type Route struct {
	handler   func(c context.Context, w http.ResponseWriter, r *http.Request)
	AuthLevel int
}

// Map - Static map of HTTP routes to their corresponding handlers
var Map = make(map[string]Route)

// Private ctx keys
type key string

// Handler - Public handler wrapper for each route
func (route Route) Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()
	// Handle authentication
	switch route.AuthLevel {
	case 1:
		id, err := Authenticate(w, r)
		if err != nil {
			return
		}
		// Add the user id to the route context
		ctx = context.WithValue(ctx, key("user"), id)
	}
	route.handler(ctx, w, r)
}

func init() {
	Map["POST:/register"] = Route{
		handler:   Register,
		AuthLevel: 0}
	Map["POST:/login"] = Route{
		handler:   Login,
		AuthLevel: 0}
	Map["DELETE:/account/delete"] = Route{
		handler:   DeleteAccount,
		AuthLevel: 1}

	Map["POST:/keys"] = Route{
		handler:   AddKeys,
		AuthLevel: 1}
	Map["GET:/keys"] = Route{
		handler:   GetKeys,
		AuthLevel: 1}

	Map["POST:/name"] = Route{
		handler:   AddName,
		AuthLevel: 1}
	Map["GET:/name"] = Route{
		handler:   GetName,
		AuthLevel: 1}
	Map["PATCH:/name"] = Route{
		handler:   UpdateName,
		AuthLevel: 1}
	Map["DELETE:/name"] = Route{
		handler:   DeleteName,
		AuthLevel: 1}

	Map["POST:/todos"] = Route{
		handler:   AddTodo,
		AuthLevel: 1}
	Map["GET:/todos"] = Route{
		handler:   GetTodos,
		AuthLevel: 1}
	Map["GET:/todos/{id}"] = Route{
		handler:   GetTodo,
		AuthLevel: 1}
	Map["PATCH:/todos/{id}"] = Route{
		handler:   UpdateTodo,
		AuthLevel: 1}
	Map["DELETE:/todos/{id}"] = Route{
		handler:   DeleteTodo,
		AuthLevel: 1}
}
