package middleware

import (
	"fmt"
	"log"
	"os"
	"time"
)

const maxLogfileSize int64 = 500000

// How often the logfile is rotated
const rotationPeriod = time.Hour

var done = make(chan bool)
var outfile *os.File

func getTimestamp() string {
	now := time.Now()
	return fmt.Sprintf("%d-%d-%d_%d-%d-%d", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
}

// RotateLogs - Make sure the logger is working with a fresh, reasonably small logfile
// (and archive any logfiles after they have exceeded a max size)
func RotateLogs(logfile string) {
	stat, err := os.Stat(logfile)
	// Stamp and archive the logfile if its size has exceeded 500kb
	if err == nil && stat.Size() > maxLogfileSize {
		outfile.Close()
		stamp := getTimestamp()
		err := os.Rename(logfile, fmt.Sprintf("%s_%s", logfile, stamp))
		if err != nil {
			log.SetOutput(os.Stdout)
			log.Fatal("Unable to archive logfile:", err)
		}
	}

	// Append or create the logfile (append is necessary in the case that the API was restarted at a time that the logfile was within the max size)
	file, err := os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.SetOutput(os.Stdout)
		log.Fatal("Unable to open logfile:", err)
	}
	outfile = file
	log.SetOutput(outfile)
}

// SetupLogger - Initialize logging
func SetupLogger(logfile string) {
	// Setup ticker to rotate logs
	RotateLogs(logfile)
	ticker := time.NewTicker(rotationPeriod)
	go func() {
		select {
		case <-done:
			outfile.Close()
			return
		case <-ticker.C:
			RotateLogs(logfile)
		}
	}()
}

// CloseLogger - Gracefully close the logger's file output
func CloseLogger() {
	done <- true
}
