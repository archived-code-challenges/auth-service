// This program performs administrative tasks for the Kokoro service.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"

	"github.com/noelruault/golang-authentication/internal/schema"
)

const logAdminName = "GOLANG-AUTHENTICATION-ADMIN"

func main() {
	if err := run(); err != nil {
		log.Printf("error: %s", err)
		os.Exit(1)
	}
}

func run() error {

	// =========================================================================
	// Configuration
	var cfg struct {
		Database struct {
			User     string `conf:"default:goauthsvc"`
			Password string `conf:"default:secret1234"`
			Name     string `conf:"default:goauthsvc"`
			Port     string `conf:"default:5432"`
			Host     string `conf:"default:0.0.0.0"`
			SSLMode  string `conf:"default:disable"`
			Timezone string `conf:"default:Europe/London"`
		}
		Args conf.Args
	}

	log := log.New(os.Stdout, fmt.Sprintf("%s :", logAdminName), log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	// Parses configuration arguments and tags
	if err := conf.Parse(os.Args[1:], logAdminName, &cfg); err != nil {
		if err == conf.ErrHelpWanted {
			usage, err := conf.Usage(logAdminName, &cfg)
			if err != nil {
				return fmt.Errorf("generating config usage %w", err)
			}
			log.Printf(usage)
			return nil
		}
		return fmt.Errorf("parsing config %w", err)
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.Port,
		cfg.Database.SSLMode,
		cfg.Database.Timezone,
	)

	db, err := schema.EstablishAsyncConnection(dsn)
	if err != nil {
		return err
	}

	switch cfg.Args.Num(0) {
	case "migrate":
		err := schema.MigrateGORM(db)
		if err != nil {
			return err
		}
	case "cleanup":
		schema.CleanupDatabase(db)

	default:
		err = errors.New("Must specify a command. e.g: <migrate>, <cleanup>")
	}

	if err != nil {
		return err
	}

	return nil
}

// keygen creates an x509 private key for signing auth tokens.
func keygen(path string) error {
	if path == "" {
		return errors.New("keygen missing argument for key path")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.Wrap(err, "generating keys")
	}

	file, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "creating private file")
	}
	defer file.Close()

	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(file, &block); err != nil {
		return errors.Wrap(err, "encoding to private file")
	}

	if err := file.Close(); err != nil {
		return errors.Wrap(err, "closing private file")
	}

	return nil
}
