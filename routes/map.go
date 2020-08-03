package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Route - Information to handle HTTP routes
type Route struct {
	handler   func(c context.Context, w http.ResponseWriter, r *http.Request)
	AuthLevel int
}

// Map - Static map of HTTP routes to their corresponding handlers
var Map = make(map[string]*Route)

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
	Map["POST:/register"] = &Route{
		handler:   Register,
		AuthLevel: 0}
	Map["POST:/login"] = &Route{
		handler:   Login,
		AuthLevel: 0}
	Map["DELETE:/account/delete"] = &Route{
		handler:   DeleteAccount,
		AuthLevel: 1}

	Map["POST:/keys"] = &Route{
		handler:   AddKeys,
		AuthLevel: 1}
	Map["GET:/keys"] = &Route{
		handler:   GetKeys,
		AuthLevel: 1}

	Map["POST:/name"] = &Route{
		handler:   AddName,
		AuthLevel: 1}
	Map["GET:/name"] = &Route{
		handler:   GetName,
		AuthLevel: 1}
	Map["PATCH:/name"] = &Route{
		handler:   UpdateName,
		AuthLevel: 1}
	Map["DELETE:/name"] = &Route{
		handler:   DeleteName,
		AuthLevel: 1}

	Map["POST:/todos"] = &Route{
		handler:   AddTodo,
		AuthLevel: 1}
	Map["GET:/todos"] = &Route{
		handler:   GetTodos,
		AuthLevel: 1}
	Map["GET:/todos/{id}"] = &Route{
		handler:   GetTodo,
		AuthLevel: 1}
	Map["PATCH:/todos/{id}"] = &Route{
		handler:   UpdateTodo,
		AuthLevel: 1}
	Map["DELETE:/todos/{id}"] = &Route{
		handler:   DeleteTodo,
		AuthLevel: 1}
}

// CatchAll - Add a catchall route for otherwise unmatched routes
func CatchAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	HTTPError(w, Error{
		Title:   "Not Found",
		Message: "The requested route could not be found",
		Status:  404})
}

var resources = [2]string{"todos", "categories"}

// Preflight - Respond to preflight requests
func Preflight(w http.ResponseWriter, r *http.Request) {
	method := r.Header.Get("Access-Control-Request-Method")
	route := Map[method+":"+r.URL.Path]
	if route != nil {
		// Run authentication if the route requires it
		if route.AuthLevel > 0 {
			_, err := Authenticate(w, r)
			if err != nil {
				return
			}
		}

		// Figure out the allowed methods for the request
		var methods []string
		for _, m := range []string{"GET", "POST", "PATCH", "DELETE"} {
			if Map[m+":"+r.URL.Path] != nil {
				methods = append(methods, m)
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
		w.WriteHeader(200) // Send a 200 response if the user is authenticated for the request

	} else { // Make sure to check if the path is referring to a resource by ID
		for _, resource := range resources {
			// Validate whether the URL path is requesting the resource
			if !strings.HasPrefix(r.URL.Path, fmt.Sprintf("/%s/", resource)) {
				continue
			}
			// Run user authentication for the request
			_, err := Authenticate(w, r)
			if err != nil {
				return
			}

			// Match all supported methods for the resource
			var methods []string
			reqMethodSupported := false // We assume that the requested method is not supported until proven otherwise
			for _, m := range []string{"GET", "POST", "PATCH", "DELETE"} {
				if Map[fmt.Sprintf("%s:/%s/{id}", m, resource)] != nil {
					methods = append(methods, m)
					if m == method {
						reqMethodSupported = true
					}
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))

			// If the requested method is supported send a 200 response, otherwise send a 405 (method not allowed)
			if reqMethodSupported {
				w.WriteHeader(200)
			} else {
				w.WriteHeader(405)
			}
			return // Don't go on to the catchall handler
		}
		CatchAll(w, r)
	}
}
