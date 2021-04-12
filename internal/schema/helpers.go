package schema

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func EstablishAsyncConnection(databaseDSN string) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	maxAttempts := 20
	for attempts := 1; attempts <= maxAttempts; attempts++ {
		// Tries to establish a connection with the database
		db, err = gorm.Open(postgres.Open(databaseDSN), &gorm.Config{})
		time.Sleep(time.Duration(attempts) * 100 * time.Millisecond)
	}

	if err != nil {
		return nil, fmt.Errorf("opening async database connection through dsl %w", err)
	}

	return db, nil
}

func EstablishConnection(databaseDSN string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(databaseDSN), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("opening database connection through dsl %w", err)
	}

	return db, nil
}

func CleanupDatabase(gdb *gorm.DB) {
	gdb.Exec("DROP SCHEMA public CASCADE")
	gdb.Exec("CREATE SCHEMA public")
}
