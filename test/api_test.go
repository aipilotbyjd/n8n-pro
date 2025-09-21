package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

func TestWorkflowAPI(t *testing.T) {
	// Create Workflow
	createWorkflowBody := []byte(`{
        "name": "My Test Workflow",
        "description": "This is a test workflow.",
        "nodes": [],
        "connections": [],
        "tags": [],
        "config": {}
    }`)
	resp, err := http.Post("http://localhost:8080/api/v1/workflows", "application/json", bytes.NewBuffer(createWorkflowBody))
	if err != nil {
		t.Fatalf("Error creating workflow: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Create workflow failed with status: %s, body: %s", resp.Status, string(bodyBytes))
	}
	fmt.Println("Create workflow successful!")

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Error decoding response: %v", err)
	}
	createdWorkflow := response["data"].(map[string]interface{})
	workflowID := createdWorkflow["id"].(string)

	// Get Workflow
	resp, err = http.Get(fmt.Sprintf("http://localhost:8080/api/v1/workflows/%s", workflowID))
	if err != nil {
		t.Fatalf("Error getting workflow: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Get workflow failed with status: %s, body: %s", resp.Status, string(bodyBytes))
	}
	fmt.Println("Get workflow successful!")

	// List Workflows
	resp, err = http.Get("http://localhost:8080/api/v1/workflows")
	if err != nil {
		t.Fatalf("Error listing workflows: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("List workflows failed with status: %s, body: %s", resp.Status, string(bodyBytes))
	}
	fmt.Println("List workflows successful!")

	// Update Workflow
	updateWorkflowBody := []byte(`{
        "name": "My Updated Test Workflow",
        "description": "This is an updated test workflow.",
        "nodes": [],
        "connections": [],
        "tags": [],
        "config": {},
        "status": "active"
    }`)
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://localhost:8080/api/v1/workflows/%s", workflowID), bytes.NewBuffer(updateWorkflowBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error updating workflow: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Update workflow failed with status: %s, body: %s", resp.Status, string(bodyBytes))
	}
	fmt.Println("Update workflow successful!")

	// Delete Workflow
	req, _ = http.NewRequest(http.MethodDelete, fmt.Sprintf("http://localhost:8080/api/v1/workflows/%s", workflowID), nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error deleting workflow: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Delete workflow failed with status: %s, body: %s", resp.Status, string(bodyBytes))
	}
	fmt.Println("Delete workflow successful!")

	fmt.Println("All workflow API tests passed!")
}
