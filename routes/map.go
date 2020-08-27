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

// AuthBypass - An unsafe bypass flag for user authentication
var AuthBypass bool = false

// Map - Static map of HTTP routes to their corresponding handlers
var Map = make(map[string]*Route)

// Private ctx keys
type key string

// Handler - Public handler wrapper for each route
func (route Route) Handler(w http.ResponseWriter, r *http.Request) {
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
	Map["GET:/whoami"] = &Route{
		handler:   WhoAmI,
		AuthLevel: 1}
	Map["DELETE:/account/delete"] = &Route{
		handler:   DeleteAccount,
		AuthLevel: 1}

	Map["POST:/challenge"] = &Route{
		handler:   RequestChallenge,
		AuthLevel: 0}
	Map["POST:/challenge/{id}"] = &Route{
		handler:   SubmitChallenge,
		AuthLevel: 0}
	Map["POST:/login"] = &Route{
		handler:   Login,
		AuthLevel: 0}

	Map["PATCH:/authkey"] = &Route{
		handler:   UpdateAuthKey,
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

	Map["POST:/tags"] = &Route{
		handler:   AddTag,
		AuthLevel: 1}
	Map["GET:/tags"] = &Route{
		handler:   GetTags,
		AuthLevel: 1}
	Map["GET:/tags/{id}"] = &Route{
		handler:   GetTag,
		AuthLevel: 1}
	Map["PATCH:/tags/{id}"] = &Route{
		handler:   UpdateTag,
		AuthLevel: 1}
	Map["DELETE:/tags/{id}"] = &Route{
		handler:   DeleteTag,
		AuthLevel: 1}

	Map["POST:/nolist"] = &Route{
		handler:   CreateNoList,
		AuthLevel: 1}
	Map["PATCH:/nolist"] = &Route{
		handler:   UpdateNoList,
		AuthLevel: 1}
	Map["GET:/nolist"] = &Route{
		handler:   GetNoList,
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
var methods = [4]string{"GET", "POST", "PATCH", "DELETE"}
var allowedOrigins = [2]string{"http://localhost:3030", "https://csplan.co"}

// Preflight - Respond to preflight requests
func Preflight(w http.ResponseWriter, r *http.Request) {
	reqMethod := r.Header.Get("Access-Control-Request-Method")
	reqMethodSupported := false
	var supportedMethods []string

	for _, method := range methods { // Don't allow access to OPTIONS requests for routes that require greater than normal user auth
		if Map[fmt.Sprintf("%s:%s", method, r.URL.Path)] == nil || Map[fmt.Sprintf("%s:%s", method, r.URL.Path)].AuthLevel > 1 {
			continue
		}
		supportedMethods = append(supportedMethods, method)
		if method == reqMethod {
			reqMethodSupported = true
		}
	}

	// If the requested method is supported send a 200 response, otherwise send a 405 (method not allowed)
	if len(supportedMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(supportedMethods, ","))
		if reqMethodSupported || len(reqMethod) == 0 { // Allow OPTIONS requests without a specified emthod
			origin := r.Header.Get("Origin")
			for _, allowed := range allowedOrigins {
				if allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, CSRF-Token")
					break
				}
			}
			w.WriteHeader(200)
		} else {
			w.WriteHeader(405)
		}
		return
	}

	// If matching a route by exact path has failed, try matching it by resource identifier
	for _, resource := range resources {
		// Validate whether the URL path is requesting the resource
		if !strings.HasPrefix(r.URL.Path, fmt.Sprintf("/%s/", resource)) {
			continue
		}

		// Match all supported methods for the resource
		for _, method := range methods {
			if Map[fmt.Sprintf("%s:/%s/{id}", method, resource)] != nil {
				supportedMethods = append(supportedMethods, method)
				if method == reqMethod {
					reqMethodSupported = true
				}
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(supportedMethods, ","))

		if reqMethodSupported || len(reqMethod) == 0 {
			origin := r.Header.Get("Origin")
			for _, allowed := range allowedOrigins {
				if allowed == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, CSRF-Token")
					break
				}
			}
			w.WriteHeader(200)
		} else {
			w.WriteHeader(405)
		}
		return // Don't go on to the catchall handler
	}
	// If all of the above has failed, send a 404
	CatchAll(w, r)
}
