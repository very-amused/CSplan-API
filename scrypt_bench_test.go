package main

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

const r = 8       // For the time being, r is constant
const keyLen = 32 // There is no security appeal to storing keys larger than this
const threadRatio = 0.75

var (
	loglevel int
	// The scrypt parallelization factor, to be calculated based on available threads
	p int

	// The 4 sets of scrypt parameters to be generated
	scryptLow     string
	scryptMedium  string
	scryptHigh    string
	scryptExtreme string

	// An average password
	password = []byte("correcthorsebatterystaple")
)

func benchmarkScryptParams(maxTime int64) (params string) {
	for i := 1; true; i++ {
		// N = 2^i
		N := 1 << i

		// Run the benchmark 5 times to ensure accurate data
		var results int64 // Track results with millisecond precision
		for i := 0; i < 5; i++ {
			// Generate a random salt
			salt := make([]byte, 16)
			start := time.Now()
			scrypt.Key(password, salt, N, r, p, keyLen)
			t := time.Now().Sub(start)
			results += t.Milliseconds()

			// Log each run (TODO: control loglevel with cli flags)
			if loglevel >= 2 {
				fmt.Printf("N = %d: %s (run %d)\n", N, t, i+1)
			}
		}
		avgResult := results / 5                                              // Take the average of all runs
		prettyResult, _ := time.ParseDuration(fmt.Sprintf("%dms", avgResult)) // Get a time.Duration form of the average runtime for pretty printing
		// If the average duration exceeds the max time passed as a parameter, the previous set of parameters are the highest acceptable
		if avgResult > maxTime {
			if loglevel >= 1 {
				fmt.Printf("\x1b[33mN = %d: avg %s\x1b[0m\n", N, prettyResult)
			}
			break
		}
		params = fmt.Sprintf("%d:%d:%d", N, r, p)
		if loglevel >= 1 {
			fmt.Printf("\x1b[32mN = %d: avg %s\x1b[0m\n", N, prettyResult)
		}
	}

	return params
}

func BenchmarkScrypt(b *testing.B) {
	// Parse env flags
	var err error
	loglevel, err = strconv.Atoi(os.Getenv("LOGLEVEL"))
	if err != nil {
		loglevel = 0
	}

	// Parallelization factor is calculated as 3/4 of the available threads, rounded to the nearest integer
	p = int(math.Ceil(0.75 * float64(runtime.NumCPU())))

	// Initialize the env file
	env, err := os.Create("scrypt.env")
	if err != nil {
		panic(err)
	}
	defer env.Close()

	// Calculate scrypt parameters
	fmt.Println("Calculating scrypt low difficulty workfactor...")
	scryptLow = benchmarkScryptParams(300)
	fmt.Println("Calculating scrypt medium difficulty workfactor...")
	scryptMedium = benchmarkScryptParams(1000)
	fmt.Println("Calculating scrypt high difficulty workfactor...")
	scryptHigh = benchmarkScryptParams(2000)
	fmt.Println("Calculating scrypt extreme difficulty workfactor...")
	scryptExtreme = benchmarkScryptParams(5000)

	// Write parameters to env file
	env.WriteString(
		fmt.Sprintf("SCRYPT_LOW=%s\nSCRYPT_MEDIUM=%s\nSCRYPT_HIGH=%s\nSCRYPT_EXTREME=%s\n",
			scryptLow, scryptMedium, scryptHigh, scryptExtreme))
}
