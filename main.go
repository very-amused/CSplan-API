package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/very-amused/CSplan-API/routes"

	"github.com/gorilla/mux"
)

func loadRoutes(r *mux.Router) {
	for key, route := range routes.Map {
		// Parse method and path from route key
		slice := strings.Split(key, ":")
		method := slice[0]
		path := slice[1]

		if route.AuthLevel < 0 || route.AuthLevel > 1 {
			log.Fatalf(`Invalid authentication level for route %s
			This can be fixed in routes/map.go`, key)
		}

		// Add route to the router (specific for each EXACT path)
		r.HandleFunc(path, route.Handler).Methods(method)
	}

	r.PathPrefix("/").HandlerFunc(routes.Preflight).Methods("OPTIONS")
	r.PathPrefix("/").HandlerFunc(routes.CatchAll)
}

func main() {
	r := mux.NewRouter()
	loadRoutes(r)

	fmt.Println("Starting up CSplan API 🚀")
	log.Fatal(http.ListenAndServe(":3000", r))
}
