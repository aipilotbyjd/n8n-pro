package db

import (
    "context"
    "github.com/jackc/pgx/v5/pgxpool"
    "log"
    "n8n-pro/internal/config"
)

var Pool *pgxpool.Pool

func Init(cfg *config.Config) {
    var err error
    Pool, err = pgxpool.New(context.Background(), cfg.DatabaseURL)
    if err != nil {
        log.Fatalf("Unable to connect to DB: %v", err)
    }
}
