package httpserver

import (
	"net/http"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"n8n-pro/internal/api/handlers"
	"n8n-pro/internal/workflows"
)

func NewServer(workflowSvc workflows.Service) *http.Server {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Health endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Workflow endpoints
	workflowHandler := handlers.NewWorkflowHandler(workflowSvc)
	r.Route("/v1/workflows", func(r chi.Router) {
		r.Get("/", workflowHandler.ListWorkflows)
		r.Post("/", workflowHandler.CreateWorkflow)
		r.Get("/{id}", workflowHandler.GetWorkflow)
		r.Put("/{id}", workflowHandler.UpdateWorkflow)
		r.Delete("/{id}", workflowHandler.DeleteWorkflow)
	})

	return &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
}
