package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/very-amused/CSplan-API/core"
	"github.com/very-amused/CSplan-API/routes/auth"
	"github.com/very-amused/CSplan-API/routes/crypto"
	"github.com/very-amused/CSplan-API/routes/profile"
	"github.com/very-amused/CSplan-API/routes/tags"
	"github.com/very-amused/CSplan-API/routes/todo"
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

// Handler - Public handler wrapper for each route
func (route Route) Handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Handle authentication
	if route.AuthLevel > 0 {
		authLvl := auth.Authenticate(w, r)
		// Send relevant 401/403 response if the user isn't properly authenticated for the route
		if authLvl.AuthLevel == -1 {
			core.WriteError(w, auth.HTTPUnauthorized)
			return
		} else if authLvl.AuthLevel < route.AuthLevel {
			core.WriteError(w, auth.HTTPForbidden)
			return
		}
		// Add the user and session id to the route context
		ctx = context.WithValue(ctx, core.Key("user"), authLvl.UserID)
		ctx = context.WithValue(ctx, core.Key("session"), authLvl.SessionID)
	}
	route.handler(ctx, w, r)
}

func init() {
	Map["POST:/register"] = &Route{
		handler:   auth.Register,
		AuthLevel: 0}
	Map["GET:/whoami"] = &Route{
		handler:   auth.WhoAmI,
		AuthLevel: 1}
	/* Two separate HTTP requests (second one must contain a token sent in the first)
	to this fairly difficult to hit by accident URL are needed to actually delete a user account,
	making it practically impossible to accomplish by accident
	*/
	Map["DELETE:/delete_my_account_please"] = &Route{
		handler:   auth.DeleteAccount,
		AuthLevel: 1}

	Map["POST:/challenge"] = &Route{
		handler:   auth.RequestChallenge,
		AuthLevel: 0}
	Map["POST:/challenge/{id}"] = &Route{
		handler:   auth.SubmitChallenge,
		AuthLevel: 0}
	Map["POST:/login"] = &Route{
		handler:   auth.Login,
		AuthLevel: 0}

	// Session management
	Map["POST:/logout"] = &Route{
		handler:   auth.Logout,
		AuthLevel: 1}
	Map["POST:/logout/{id}"] = &Route{
		handler:   auth.Logout,
		AuthLevel: 2}
	Map["GET:/sessions"] = &Route{
		handler:   auth.GetSessions,
		AuthLevel: 1}

	Map["PATCH:/authkey"] = &Route{
		handler:   auth.UpdateKey,
		AuthLevel: 1}

	Map["POST:/keys"] = &Route{
		handler:   crypto.AddKeys,
		AuthLevel: 1}
	Map["GET:/keys"] = &Route{
		handler:   crypto.GetKeys,
		AuthLevel: 1}
	Map["PATCH:/keys"] = &Route{
		handler:   crypto.UpdateKeys,
		AuthLevel: 1}

	Map["GET:/settings"] = &Route{
		handler:   profile.GetSettings,
		AuthLevel: 1}
	Map["PATCH:/settings"] = &Route{
		handler:   profile.UpdateSettings,
		AuthLevel: 1}

	Map["POST:/name"] = &Route{
		handler:   profile.AddName,
		AuthLevel: 1}
	Map["GET:/name"] = &Route{
		handler:   profile.GetName,
		AuthLevel: 1}
	Map["PATCH:/name"] = &Route{
		handler:   profile.UpdateName,
		AuthLevel: 1}
	Map["DELETE:/name"] = &Route{
		handler:   profile.DeleteName,
		AuthLevel: 1}

	Map["POST:/todos"] = &Route{
		handler:   todo.AddTodo,
		AuthLevel: 1}
	Map["GET:/todos"] = &Route{
		handler:   todo.GetTodos,
		AuthLevel: 1}
	Map["GET:/todos/{id}"] = &Route{
		handler:   todo.GetTodo,
		AuthLevel: 1}
	Map["PATCH:/todos/{id}"] = &Route{
		handler:   todo.UpdateTodo,
		AuthLevel: 1}
	Map["DELETE:/todos/{id}"] = &Route{
		handler:   todo.DeleteTodo,
		AuthLevel: 1}

	Map["POST:/tags"] = &Route{
		handler:   tags.AddTag,
		AuthLevel: 1}
	Map["GET:/tags"] = &Route{
		handler:   tags.GetTags,
		AuthLevel: 1}
	Map["GET:/tags/{id}"] = &Route{
		handler:   tags.GetTag,
		AuthLevel: 1}
	Map["PATCH:/tags/{id}"] = &Route{
		handler:   tags.UpdateTag,
		AuthLevel: 1}
	Map["DELETE:/tags/{id}"] = &Route{
		handler:   tags.DeleteTag,
		AuthLevel: 1}

	Map["POST:/nolist"] = &Route{
		handler:   todo.CreateNoList,
		AuthLevel: 1}
	Map["PATCH:/nolist"] = &Route{
		handler:   todo.UpdateNoList,
		AuthLevel: 1}
	Map["GET:/nolist"] = &Route{
		handler:   todo.GetNoList,
		AuthLevel: 1}
}

// CatchAll - Add a catchall route for otherwise unmatched routes
func CatchAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	core.WriteError(w, core.HTTPError{
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
