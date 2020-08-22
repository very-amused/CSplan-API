package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
)

const keyLen = 32 // There is no security appeal to storing keys larger than this
const threadRatio = 0.75

var (
	// The verbosity of logs to be printed
	loglevel int
	// The scrypt parallelization factor, to be calculated based on available threads
	p int

	// An average password
	password = []byte("correcthorsebatterystaple")
)

func benchmarkScryptParams(maxRuntime time.Duration) (params string) {
	// Safe defaults (recommended by scrypt)
	var N int = 32768
	var r int = 8

	// Benchmark the n parameter
	for i := N; true; i = i * 2 {
		tempN := i

		// Run the benchmark 5 times to ensure accurate data
		var results time.Duration
		for i := 0; i < 5; i++ {
			// Generate a random salt
			salt := make([]byte, 16)
			rand.Read(salt)
			start := time.Now()
			scrypt.Key(password, salt, tempN, r, p, keyLen)
			elapsed := time.Now().Sub(start)
			results += elapsed

			// Log each run
			if loglevel >= 2 {
				fmt.Printf("N = %d: %s (run %d)\n", tempN, elapsed, i+1)
			}
		}
		avg := results / 5 // Take the average of all runs
		// If the average duration exceeds the max time passed as a parameter, the previous set of parameters are the highest acceptable
		if avg > maxRuntime {
			if loglevel >= 1 {
				fmt.Printf("\x1b[33mN = %d: avg %s\x1b[0m\n", tempN, avg)
			}
			break
		}

		// Log the result as successful, and update the N value
		if loglevel >= 1 {
			fmt.Printf("\x1b[32mN = %d: avg %s\x1b[0m\n", tempN, avg)
		}
		N = tempN
	}

	// Benchmark the R parameter
	for i := r; true; i++ {
		tempR := i

		var results time.Duration
		for i := 0; i < 5; i++ {
			// Generate a random salt
			salt := make([]byte, 16)
			rand.Read(salt)
			start := time.Now()
			scrypt.Key(password, salt, N, tempR, p, keyLen)
			elapsed := time.Now().Sub(start)
			results += elapsed

			// Log each run
			if loglevel >= 2 {
				fmt.Printf("r = %d: %s (run %d)\n", tempR, elapsed, i+1)
			}
		}
		avg := results / 5
		if avg > maxRuntime {
			if loglevel >= 1 {
				fmt.Printf("\x1b[33mr = %d: avg %s\x1b[0m\n", tempR, avg)
			}
			break
		}

		if loglevel >= 1 {
			fmt.Printf("\x1b[32mr = %d: avg %s\x1b[0m\n", tempR, avg)
		}
		r = tempR
	}

	// Format parameters
	params = fmt.Sprintf("%d:%d:%d", N, r, p)
	if loglevel >= 1 {
		fmt.Printf("\x1b[36mFinal calculated parameter set: %s\x1b[0m\n", params)
	}

	return fmt.Sprintf("%d:%d:%d", N, r, p)
}

func BenchmarkScrypt(b *testing.B) {
	// Parse env flags
	var err error
	loglevel, err = strconv.Atoi(os.Getenv("LOGLEVEL"))
	if err != nil {
		loglevel = 1
	}

	// Parallelization factor is calculated as 3/4 of the available threads, rounded to the nearest integer
	p = int(math.Ceil(threadRatio * float64(runtime.NumCPU())))

	// Initialize the env file
	env, err := os.Create("scrypt.env")
	if err != nil {
		panic(err)
	}
	defer env.Close()

	// Calculate each set of scrypt parameters
	fmt.Println("Calculating scrypt normal difficulty params...")
	normal := benchmarkScryptParams(time.Second * 1)
	env.WriteString(fmt.Sprintf("export SCRYPT_NORMAL=%s\n", normal))

	fmt.Println("Calculating scrypt high difficulty params...")
	high := benchmarkScryptParams(time.Second * 2)
	env.WriteString(fmt.Sprintf("export SCRYPT_HIGH=%s\n", high))

	fmt.Println("Calculating scrypt extreme difficulty params...")
	extreme := benchmarkScryptParams(time.Second * 5)
	env.WriteString(fmt.Sprintf("export SCRYPT_EXTREME=%s\n", extreme))
}
