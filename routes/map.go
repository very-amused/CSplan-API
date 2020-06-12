package routes

import "net/http"

// Map - Static map of HTTP routes to their corresponding handlers
var Map = make(map[string]func(w http.ResponseWriter, r *http.Request))

func init() {
	Map["POST:/register"] = Register

	Map["POST:/login"] = Login
}
