package analyzer

// PromptAnalyzeFinding is the prompt template for analyzing a single finding.
const PromptAnalyzeFinding = `Analyze the following security finding and provide an enhanced, actionable fix suggestion:

Title: %s
Description: %s
Severity: %s
Current Suggestion: %s

Please provide:
1. A brief explanation of why this is a security risk
2. Step-by-step remediation instructions
3. Code example of the fix if applicable
4. Prevention recommendations
`

// PromptSummarizeFindings is the prompt template for summarizing multiple findings.
const PromptSummarizeFindings = `Summarize the following security scan findings and provide an overall risk assessment and prioritized remediation plan:

%s

Please provide:
1. Overall risk level (Critical/High/Medium/Low)
2. Top 3 priorities to fix immediately
3. Grouped recommendations by category
4. Estimated effort for remediation
`
