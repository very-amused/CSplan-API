package routes

import (
	"fmt"
	"log"
	"os"

	"github.com/jmoiron/sqlx"

	// MySQL Database driver
	_ "github.com/go-sql-driver/mysql"
)

// DB - MariaDB Connection Pool
var DB *sqlx.DB

// DB constants
var user string = "admin"
var password string = os.Getenv("MARIADB_PASSWORD")
var database string = "CSplanGo"

// dsn - Return SQL data source name
func dsn() string {
	return fmt.Sprintf("%s:%s@/%s", user, password, database)
}

func init() {
	db, err := sqlx.Connect("mysql", dsn())
	if err != nil {
		log.Fatal(err)
	}
	DB = db
	DB.MapperFunc(func(s string) string {
		return s
	}) // Disable automatic mapping of column names to lowercase (both columns and structs are in PascalCase)
}
