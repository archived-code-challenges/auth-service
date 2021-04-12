package main

import (
	"context"
	_ "expvar" // Register the expvar handlers
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // Register the pprof handlers
	"os"
	"os/signal"
	"syscall"
	"time"

	"contrib.go.opencensus.io/exporter/zipkin"
	"github.com/ardanlabs/conf"
	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/noelruault/golang-authentication/internal/handlers"
)

const logServiceName = "GOLANG-AUTHENTICATION-SERVICE"

var cfg struct {
	Services struct {
		// JWTSecret is used to sign the JWT tokens used to identify users.
		JWTSecret []byte
	}
	Web struct {
		Address         string        `conf:"default:0.0.0.0:8080"`
		Debug           string        `conf:"default:0.0.0.0:6060"`
		ReadTimeout     time.Duration `conf:"default:5s"`
		WriteTimeout    time.Duration `conf:"default:5s"`
		ShutdownTimeout time.Duration `conf:"default:5s"`
	}
	Database struct {
		User     string `conf:"default:goauthsvc"`
		Password string `conf:"default:secret1234"`
		Name     string `conf:"default:goauthsvc"`
		Port     string `conf:"default:5432"`
		Host     string `conf:"default:0.0.0.0"`
		SSLMode  string `conf:"default:disable"`
		Timezone string `conf:"default:Europe/London"`
	}
	Trace struct {
		URL     string `conf:"default:http://0.0.0.0:9411/api/v2/spans"`
		Service string `conf:"default:golang-authentication-service"`
		// Probability determines how the traces should be displayed, with 1 being 100% coverage.
		Probability float64 `conf:"default:1"`
	}
}

func main() {
	if err := run(); err != nil {
		log.Println("shutting down", "error:", err)
		os.Exit(1)
	}
}

func run() error {
	log := log.New(os.Stdout, fmt.Sprintf("%s :", logServiceName), log.LstdFlags|log.Lmicroseconds|log.Lshortfile)

	// =========================================================================
	// Parses configuration arguments and tags
	if err := conf.Parse(os.Args[1:], logServiceName, &cfg); err != nil {
		if err == conf.ErrHelpWanted {
			usage, err := conf.Usage(logServiceName, &cfg)
			if err != nil {
				return fmt.Errorf("generating config usage: %w", err)
			}
			log.Printf(usage)
			return nil
		}
		return fmt.Errorf("parsing config: %w", err)
	}

	log.Printf("main : Started")
	defer log.Println("main : Completed")

	out, err := conf.String(&cfg)
	if err != nil {
		return fmt.Errorf("generating config for output: %w", err)
	}
	log.Printf("main : Config :\n%v\n", out)

	// =========================================================================
	// Storage service
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		cfg.Database.Host,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.Port,
		cfg.Database.SSLMode,
		cfg.Database.Timezone,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("opening database connection through dsl: %w", err)
	}

	// =========================================================================
	// Start Tracing Support
	closer, err := registerTracer(
		cfg.Trace.Service,
		cfg.Web.Address,
		cfg.Trace.URL,
		cfg.Trace.Probability,
	)
	if err != nil {
		return err
	}
	defer closer()

	// =========================================================================
	// Start Debug Service
	//
	// /debug/pprof - Added to the default mux by importing the net/http/pprof package.
	//
	// Not concerned with shutting this down when the application is shutdown.
	go func() {
		log.Println("debug service listening on", cfg.Web.Debug)
		err := http.ListenAndServe(cfg.Web.Debug, http.DefaultServeMux)
		log.Println("debug service closed", err)
	}()

	// =========================================================================
	// Start API Service
	//
	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	api := http.Server{
		Addr:         cfg.Web.Address,
		Handler:      handlers.API(shutdown, log, db, cfg.Services.JWTSecret),
		ReadTimeout:  cfg.Web.ReadTimeout,
		WriteTimeout: cfg.Web.WriteTimeout,
	}

	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	// Start the service listening for requests.
	go func() {
		log.Printf("main : API listening on %s", api.Addr)
		serverErrors <- api.ListenAndServe()
	}()

	// =========================================================================
	// Shutdown
	//
	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		return fmt.Errorf("starting server: %w", err)

	case sig := <-shutdown:
		log.Printf("main : %v : Start shutdown", sig)

		// Give outstanding requests a deadline for completion.
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
		defer cancel()

		// Asking listener to shutdown and load shed.
		err := api.Shutdown(ctx)
		if err != nil {
			log.Printf("main : Graceful shutdown did not complete in %v : %v", cfg.Web.ShutdownTimeout, err)
			err = api.Close()
		}

		// Log the status of this shutdown.
		switch {
		case sig == syscall.SIGSTOP:
			return errors.New("integrity issue caused shutdown")
		case err != nil:
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}
	}

	return nil
}

func registerTracer(service, httpAddr, traceURL string, probability float64) (func() error, error) {
	localEndpoint, err := openzipkin.NewEndpoint(service, httpAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to create local zipkinEndpoint: %w", err)
	}
	reporter := zipkinHTTP.NewReporter(traceURL)

	trace.RegisterExporter(zipkin.NewExporter(reporter, localEndpoint))
	trace.ApplyConfig(trace.Config{
		DefaultSampler: trace.ProbabilitySampler(probability),
	})

	return reporter.Close, nil
}
