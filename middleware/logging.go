package middleware

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// How big a single logfile is permitted to grow
const maxLogfileSize int64 = 500000

// How often the logfile's size is checked
const rotationPeriod = time.Hour

var outfile *os.File

func getTimestamp() string {
	now := time.Now()
	return fmt.Sprintf("%d-%d-%d_%d:%d:%d", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
}

// RotateLogs - Make sure the logger is working with a fresh, reasonably small logfile
// (and archive any logfiles after they have exceeded a max size)
func RotateLogs(logfile string) {
	stat, err := os.Stat(logfile)
	// Stamp and archive the logfile if its size has exceeded 500kb
	if err == nil && stat.Size() > maxLogfileSize {
		outfile.Close()
		stamp := getTimestamp()
		// Split logfile extension
		parts := strings.Split(logfile, ".")
		if len(parts) > 2 {
			parts[1] = ""
		} else {
			// Append dot to extension
			parts[1] = "." + parts[1]
		}

		// Archive old logfile
		err := os.Rename(logfile, fmt.Sprintf("%s_%s%s", parts[0], stamp, parts[1]))
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
		case <-ticker.C:
			RotateLogs(logfile)
		}
	}()
}
