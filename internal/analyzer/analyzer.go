package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/noah/sherlock/internal/vulndb"
)

// LLMAnalyzer analyzes findings using an LLM backend.
type LLMAnalyzer struct {
	baseURL   string
	apiKey    string
	model     string
	httpClient *http.Client
}

// NewLLMAnalyzer creates a new LLM analyzer.
func NewLLMAnalyzer(baseURL, apiKey, model string) *LLMAnalyzer {
	if baseURL == "" {
		baseURL = "http://localhost:11434/v1"
	}
	if model == "" {
		model = "llama3"
	}
	return &LLMAnalyzer{
		baseURL:    baseURL,
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{Timeout: 2 * time.Minute},
	}
}

// AnalyzeFinding sends a finding to the LLM for analysis and enhanced fix suggestion.
func (a *LLMAnalyzer) AnalyzeFinding(ctx context.Context, finding *vulndb.Finding) (*vulndb.Finding, error) {
	prompt := fmt.Sprintf(PromptAnalyzeFinding, finding.Title, finding.Description, finding.Severity, finding.FixSuggestion)

	resp, err := a.queryLLM(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("llm query failed: %w", err)
	}

	finding.FixSuggestion = resp
	return finding, nil
}

// SummarizeFindings generates a summary of all findings.
func (a *LLMAnalyzer) SummarizeFindings(ctx context.Context, findings []vulndb.Finding) (string, error) {
	data, _ := json.MarshalIndent(findings, "", "  ")
	prompt := fmt.Sprintf(PromptSummarizeFindings, string(data))

	return a.queryLLM(ctx, prompt)
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (a *LLMAnalyzer) queryLLM(ctx context.Context, prompt string) (string, error) {
	reqBody := chatRequest{
		Model: a.model,
		Messages: []message{
			{Role: "system", Content: "You are a cybersecurity expert assistant. Analyze security findings and provide actionable fix suggestions."},
			{Role: "user", Content: prompt},
		},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Error != nil {
		return "", fmt.Errorf("llm error: %s", result.Error.Message)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}

	return result.Choices[0].Message.Content, nil
}
