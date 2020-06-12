package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/very-amused/CSplan-API/routes"

	"github.com/gorilla/mux"
)

func loadMiddleware(r *mux.Router) {
	r.Use(setContentType)
}

func loadRoutes(r *mux.Router) {
	for key, handler := range routes.Map {
		// Parse method and path from route key
		slice := strings.Split(key, ":")
		method := slice[0]
		path := slice[1]

		// Add route to the router (specific for each EXACT path)
		r.HandleFunc(path, handler).Methods(method)
	}

	// Add a catchall route for otherwise unmatched routes
	catchall := func(w http.ResponseWriter, r *http.Request) {
		routes.HTTPError(w, routes.Error{
			Title:   "Not Found",
			Message: "The requested route could not be found",
			Status:  404})
	}
	r.PathPrefix("/").HandlerFunc(catchall)
}

func main() {
	r := mux.NewRouter()
	loadMiddleware(r)
	loadRoutes(r)

	fmt.Println("Starting up CSplan API 🚀")
	log.Fatal(http.ListenAndServe(":3000", r))
}
