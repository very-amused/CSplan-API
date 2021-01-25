package core

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
var User = "admin"
var password = os.Getenv("MARIADB_PASSWORD")

const database = "CSplanGo"

// dsn - Return SQL data source name
func dsn() string {
	return fmt.Sprintf("%s:%s@/%s", User, password, database)
}

// Connect to the database, should be called after parsing flags
func DBConnect() {
	db, err := sqlx.Connect("mysql", dsn())
	if err != nil {
		log.Fatalf("Failed to connect to MariaDB:\n%s", err)
	}
	DB = db
	DB.MapperFunc(func(s string) string {
		return s
	}) // Disable automatic mapping of column names to lowercase (both columns and structs are in PascalCase)
}
