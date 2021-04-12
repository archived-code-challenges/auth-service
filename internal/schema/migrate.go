package schema

import (
	"fmt"

	_ "gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/noelruault/golang-authentication/internal/models"
)

// MigrateGORM generates the queries needed to construct the database schema.
// Also generates migrations if a previous state of the schema is found.
// Entries should never be removed from this slice once they have been ran in production.
func MigrateGORM(gdb *gorm.DB) error {
	var models = []interface{}{
		&models.User{},
	}

	var err error
	for _, m := range models {
		err = gdb.AutoMigrate(m)
		if err != nil {
			return fmt.Errorf("failed to create default values when migrating: %w", err)
		}
	}

	return nil
}
