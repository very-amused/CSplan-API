package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/very-amused/CSplan-API/middleware"

	"github.com/very-amused/CSplan-API/routes"

	"github.com/gorilla/mux"
)

var logfile string

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

func loadMiddleware(r *mux.Router) {
	r.Use(middleware.SetContentType)
	r.Use(middleware.CORS)
	if len(logfile) > 0 {
		middleware.SetupLogger(logfile)
	}
}

func parseFlags() {
	// Handle auth bypass (used in development to avoid the tediousness of a crypto challenge handshake)
	flag.BoolVar(&routes.AuthBypass, "allow-auth-bypass", false, "Bypass the authentication system for the purpose of running tests in development.")
	flag.StringVar(&logfile, "logfile", "", "File path for logging output. (rotation is handled in-house, old log files will be timestamped)")
	flag.Parse()
	if routes.AuthBypass && os.Getenv("CSPLAN_NO_BYPASS_WARNING") != "true" {
		fmt.Println("\x1b[31mSECURITY WARNING: Authentication bypass is enabled.\n",
			"This flag allows users to completely and totally bypass the authentication system, and MUST NOT be used in production.\n",
			"To disable this message, set the environment variable CSPLAN_NO_BYPASS_WARNING to 'true'.\x1b[0m")
	}
}

func main() {
	r := mux.NewRouter()
	parseFlags()
	loadMiddleware(r)
	loadRoutes(r)

	srv := http.Server{
		Addr:         ":3000",
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second * 10,
		Handler:      r}

	log.Println("Starting up CSplan API 🚀")
	// TLS is a requirement for HTTP2 compliance
	log.Fatal(srv.ListenAndServe())
}
