package handlers

import (
	"context"
	"net/http"

	"go.opencensus.io/trace"
	"gorm.io/gorm"

	"github.com/noelruault/golang-authentication/internal/web"
)

// Check provides support for orchestration health checks.
type Check struct {
	db *gorm.DB
}

// Health validates the service is healthy and ready to accept requests.
func (c *Check) Health(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.Check.Health")
	defer span.End()

	var health struct {
		Status string `json:"status"`
	}

	if pinger, ok := c.db.ConnPool.(interface{ Ping() error }); ok {
		err := pinger.Ping()
		if err != nil {
			health.Status = "database couldn't be reached"
			return web.Respond(ctx, w, health, http.StatusInternalServerError)
		}
		if !ok {
			health.Status = "database driver/type not supported"
			return web.Respond(ctx, w, health, http.StatusInternalServerError)
		}
	}

	health.Status = "ok"
	return web.Respond(ctx, w, health, http.StatusOK)
}
