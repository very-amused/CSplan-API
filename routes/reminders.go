package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis"
)

// Init redis
var ctx = context.Background()
var rdb = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // TODO: implement password
	DB:       0})

// Two tickers are stored, one to move upcoming reminders to the redis cache, and the other to notify users at the timestamp of areminder
var cacheTicker *time.Ticker
var queryTicker *time.Ticker

func init() {
	if true {
		return
	}

	if _, err := rdb.Ping().Result(); err != nil {
		log.Fatalf("Failed to connect to redis:\n%s", err)
	}

	// Set caching and query functions on tickers, and run each in its own goroutine
	cacheTicker = time.NewTicker(time.Minute)
	queryTicker = time.NewTicker(time.Second)

	// TODO: implement error logging in reminder goroutines
	go func() {
		for {
			<-cacheTicker.C
			go cacheReminders()
		}
	}()
	go func() {
		for {
			<-queryTicker.C
			go queryReminders(time.Now().Unix())
		}
	}()
}

// Reminder - A reminder for a user (human friendly form)
type Reminder struct {
	ID         uint   `json:"-"`
	EncodedID  string `json:"id"`
	UserID     uint   `json:"-"`
	Title      string `json:"title" validate:"required"`
	Timestamp  uint   `json:"timestamp" db:"_Timestamp"`
	RetryAfter uint   `json:"retryAfter" validate:"max=86400"`
}

// RedisFriendlyReminder - A reminder for a user (redis encoding/decoding friendly form)
type RedisFriendlyReminder struct {
	Reminder
	ID        uint   `json:"id"`
	EncodedID string `json:"-"`
	UserID    uint   `json:"userID"`
}

func (reminder *Reminder) insert() error {
	// If the timestamp is less or equal to 5 minutes in the future, it goes directly to redis, otherwise it's stored in MariaDB
	if reminder.Timestamp-uint(time.Now().Unix()) <= uint(time.Minute*5) {
		// Encode the reminder as json
		r, _ := json.Marshal(reminder)
		encodedReminder := string(r)
		_, err := rdb.LPush(fmt.Sprintf("Reminders:%d", reminder.Timestamp), encodedReminder).Result()
		return err
	}

	_, err := DB.Exec("INSERT INTO Reminders (ID, UserID, Title, _Timestamp, RetryAfter) VALUES (?, ?, ?, ?)",
		reminder.ID, reminder.UserID, reminder.Title, reminder.Timestamp)
	return err
}

// cacheReminders - Move any reminders that are 5 minutes in the future or sooner to redis
// (they still should stay in MariaDB until they're deleted by queryReminders)
// This should be called once every minute
func cacheReminders() {
	rows, _ := DB.Query("SELECT UserID, Title, _Timestamp FROM Reminders WHERE _Timestamp - UNIX_TIMESTAMP() <= 300")
	defer rows.Close()
	for rows.Next() {
		var reminder RedisFriendlyReminder
		rows.Scan(&reminder)
		if err := reminder.insert(); err != nil {
			log.Printf("Error caching reminder with id %d: %s\n", reminder.ID, err)
		}
	}
}

// queryReminders - Notify the corresponding user of each reminder set for a given second
// This should be called once every second
func queryReminders(now int64) {
	// Select all reminders scheduled for now
	values, _ := rdb.LRange(fmt.Sprintf("Reminders:%d", now), 0, -1).Result()
	for _, v := range values {
		var reminder RedisFriendlyReminder
		// Decode each key from json
		json.Unmarshal([]byte(v), &reminder)
		// TODO: implement push notifications

		// If the notification is sent successfully AND confirmed, defer its deletion, else postpone it by the user specified time
		if true { // TODO: replace with check if webpush notif was sent successfully and not postponed
			defer DB.Exec("DELETE FROM Reminders WHERE ID = ?", reminder.ID)
		} else {
			defer DB.Exec("UPDATE Reminders SET _Timestamp = ? WHERE ID = ?",
				reminder.Timestamp+reminder.RetryAfter, reminder.ID)
		}
	}

	// Delete all of these reminders from redis
	rdb.Del(fmt.Sprintf("Reminders:%d", now))
}
