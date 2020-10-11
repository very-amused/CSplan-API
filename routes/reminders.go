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
var done = make(chan bool)

// StopTickers - Stop all tickers related to reminders gracefully
func StopTickers() {
	cacheTicker.Stop()
	queryTicker.Stop()
	done <- true
}

func init() {
	if _, err := rdb.Ping().Result(); err != nil {
		log.Fatal(err)
	}

	// Set caching and query functions on tickers, and run each in its own goroutine
	cacheTicker = time.NewTicker(time.Minute)
	queryTicker = time.NewTicker(time.Second)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-cacheTicker.C:
				cacheReminders()
			}
		}
	}()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-queryTicker.C:
				queryReminders(time.Now().Unix())
			}
		}
	}()
}

// Reminder - A reminder for a user
type Reminder struct {
	ID        uint   `json:"-"`
	UserID    uint   `json:"-"`
	Title     string `json:"title" validate:"required"`
	Sent      bool   `json:"-"`
	Timestamp uint   `json:"timestamp"`
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

	_, err := DB.Exec("INSERT INTO Reminders (UserID, Title, Timestamp) VALUES (?, ?, ?)",
		reminder.UserID, reminder.Title, reminder.Timestamp)
	return err
}

// cacheReminders - Move any reminders that are 5 minutes in the future or sooner to redis
// (they still should stay in MariaDB until they're deleted by queryReminders)
// This should be called once every minute
func cacheReminders() {
	rows, _ := DB.Query("SELECT UserID, Title, Timestamp FROM Reminders WHERE Timestamp - UNIX_TIMESTAMP() <= 300")
	defer rows.Close()
	for rows.Next() {
		var reminder Reminder
		rows.Scan(&reminder)
		reminder.insert()
	}
}

// queryReminders - Notify the corresponding user of each reminder set for a given second
// This should be called once every second
func queryReminders(now int64) {
	// Select all reminders scheduled for now
	values, _ := rdb.LRange(fmt.Sprintf("Reminders:%d", now), 0, -1).Result()
	reminders := make([]Reminder, len(values))
	for i, v := range values {
		var reminder Reminder
		// Decode each key from json
		json.Unmarshal([]byte(v), &reminder)
		reminders[i] = reminder
		// TODO: implement push notifications

		// If the notification is sent successfully, flag the reminder for deletion, else postpone it by 5 minutes
		if true {
			reminders[i].Sent = true
		} else {
			reminders[i].Sent = false
			reminders[i].Timestamp += 300
		}
	}

	// Delete all of these reminders from redis
	rdb.Del(fmt.Sprintf("Reminders:%d", now))
	// Delete all successfully sent reminders from mariadb, postpone all unsuccessful ones
	for _, r := range reminders {
		go func(r Reminder) {
			var err error
			if r.Sent {
				_, err = DB.Exec("DELETE FROM Reminders WHERE ID = ?", r.ID)
			} else if !r.Sent || err != nil {
				DB.Exec("UPDATE Reminders SET Timestamp = ? WHERE ID = ?", r.Timestamp, r.ID)
			}
		}(r)
	}
}
