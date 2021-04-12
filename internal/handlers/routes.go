package handlers

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"

	mw "github.com/noelruault/golang-authentication/internal/middleware"
	"github.com/noelruault/golang-authentication/internal/models"
	"github.com/noelruault/golang-authentication/internal/web"
)

// API constructs an http.Handler with all application routes defined.
func API(
	shutdown chan os.Signal,
	log *log.Logger,
	db *gorm.DB,
	JWTSecret []byte,
) http.Handler {

	r := chi.NewRouter()
	r.Mount("/api/", r)

	// Construct the web.App which holds all routes as well as common Middleware and router.
	app := web.NewApp(shutdown, log, r, mw.Logger(log), mw.Errors(log), mw.Metrics(), mw.Panics(log))

	// Model services
	usm := models.NewUserService(db, JWTSecret)

	{
		// Register health check handler. This route is not authenticated.
		c := Check{db: db}
		app.Handle(http.MethodGet, "/", c.Health)
		app.Handle(http.MethodGet, "/health/", c.Health)
	}
	{
		usvc := NewUsers(usm, log)
		app.Handle(http.MethodPost, "/users/", usvc.Create)
		app.Handle(http.MethodGet, "/users/{user_id}", usvc.ByID)
		app.Handle(http.MethodGet, "/users/", usvc.List)
		app.Handle(http.MethodPut, "/users/{user_id}", usvc.Update)
		app.Handle(http.MethodDelete, "/users/{user_id}", usvc.Delete, mw.Authenticate(usm), mw.Me())

		app.Handle(http.MethodPost, "/oauth/login/", usvc.Login)
		app.Handle(http.MethodPost, "/oauth/login/bench/", usvc.BenchLogin) // Used to benchmark. Instructional use only.
	}

	return app
}
