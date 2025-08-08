package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

type JiraIssue struct {
	Key    string `json:"key"`
	Fields struct {
		Summary string `json:"summary"`
		Status  struct {
			Name string `json:"name"`
		} `json:"status"`
	} `json:"fields"`
}

type JiraTransitions struct {
	Transitions []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"transitions"`
}

var (
	verbose bool
	rootCmd = &cobra.Command{Use: "jiragit"}
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Open a GitHub pull request and move JIRA ticket to 'In Review'",
	Run: func(cmd *cobra.Command, args []string) {
		jiraBaseURL, jiraEmail, jiraToken := loadEnv()
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(jiraEmail+":"+jiraToken))

		branch := getCurrentBranch()
		verboseLog("Using current branch: %s", branch)

		ticketID := extractTicketID(branch)
		if ticketID == "" {
			log.Fatalf("Could not extract ticket ID from branch: %s", branch)
		}

		if dryRun {
			log.Printf("[dry-run] Would push branch and create PR")
		} else {
			pushBranch(branch)
			createPR(branch)
		}

		if dryRun {
			log.Printf("[dry-run] Would move JIRA ticket %s to In Review", ticketID)
		} else {
			moveToState(jiraBaseURL, ticketID, "In Review", authHeader)
		}
	},
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `To load completions:

Bash:
  $ source <(jiragit completion bash)
  $ jiragit completion bash > ~/.bashrc.d/jiragit.sh

Zsh:
  $ source <(jiragit completion zsh)
  $ jiragit completion zsh > "${fpath[1]}/_jiragit"

Fish:
  $ jiragit completion fish | source
  $ jiragit completion fish > ~/.config/fish/completions/jiragit.fish
`,
	DisableFlagsInUseLine: true,
	Args:                  cobra.ExactValidArgs(1),
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			rootCmd.GenPowerShellCompletion(os.Stdout)
		}
	},
}

func main() {
	startCmd := &cobra.Command{
		Use:   "start TICKET-ID",
		Short: "Create git branch and move JIRA ticket to In Progress",
		Args:  cobra.ExactArgs(1),
		Run:   runStart,
	}

	startCmd.Flags().Bool("dry-run", false, "Only print actions, don’t run them")
	startCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	reviewCmd.Flags().Bool("dry-run", false, "Only print actions, don’t run them")
	reviewCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(reviewCmd)
	rootCmd.AddCommand(completionCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func verboseLog(format string, v ...interface{}) {
	if verbose {
		log.Printf(format, v...)
	}
}

func loadEnv() (string, string, string) {
	baseURL := os.Getenv("JIRA_BASE_URL")
	email := os.Getenv("JIRA_EMAIL")
	token := os.Getenv("JIRA_API_TOKEN")

	if baseURL == "" || email == "" || token == "" {
		log.Fatal("Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN env vars")
	}
	return baseURL, email, token
}

func runStart(cmd *cobra.Command, args []string) {
	jiraBaseURL, jiraEmail, jiraToken := loadEnv()
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	ticketID := args[0]
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(jiraEmail+":"+jiraToken))

	issue := getJiraIssue(jiraBaseURL, ticketID, authHeader)
	slug := sanitize(issue.Fields.Summary)
	branchName := fmt.Sprintf("%s-%s", strings.ToUpper(ticketID), slug)

	verboseLog("Target branch: %s", branchName)

	if dryRun {
		log.Printf("[dry-run] Skipping git branch creation")
	} else {
		createGitBranch(branchName)
	}

	if issue.Fields.Status.Name != "In Progress" {
		if dryRun {
			log.Printf("[dry-run] Would move ticket %s to In Progress", ticketID)
		} else {
			moveToInProgress(jiraBaseURL, ticketID, authHeader)
		}
	} else {
		log.Printf("Ticket %s is already In Progress", ticketID)
	}
}

func getJiraIssue(jiraBaseURL, ticketID, authHeader string) JiraIssue {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/rest/api/3/issue/%s", jiraBaseURL, ticketID), nil)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	fmt.Println(resp)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("Failed to fetch ticket %s: %v", ticketID, err)
	}
	defer resp.Body.Close()

	var issue JiraIssue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		log.Fatalf("Failed to parse JIRA response: %v", err)
	}
	return issue
}

func sanitize(title string) string {
	re := regexp.MustCompile(`[^a-z0-9]+`)
	slug := re.ReplaceAllString(strings.ToLower(title), "-")
	return strings.Trim(slug, "-")
}

func createGitBranch(branch string) {
	cmd := exec.Command("git", "checkout", "-b", branch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	verboseLog("Running: git checkout -b %s", branch)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Git branch creation failed: %v", err)
	}
}

func moveToInProgress(jiraBaseURL, ticketID, authHeader string) {
	transitions := getJiraTransitions(jiraBaseURL, ticketID, authHeader)
	var inProgressID string
	for _, t := range transitions.Transitions {
		if t.Name == "In Progress" {
			inProgressID = t.ID
			break
		}
	}
	if inProgressID == "" {
		log.Printf("No transition to In Progress found")
		return
	}

	body, _ := json.Marshal(map[string]map[string]string{
		"transition": {"id": inProgressID},
	})

	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/rest/api/3/issue/%s/transitions", jiraBaseURL, ticketID), bytes.NewBuffer(body))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 300 {
		log.Printf("Failed to move ticket: %v", err)
	} else {
		log.Printf("Moved ticket %s to In Progress", ticketID)
	}
}

func getJiraTransitions(jiraBaseURL, ticketID, authHeader string) JiraTransitions {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/rest/api/3/issue/%s/transitions", jiraBaseURL, ticketID), nil)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("Failed to get transitions: %v", err)
	}
	defer resp.Body.Close()

	var t JiraTransitions
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		log.Fatalf("Failed to decode transitions: %v", err)
	}
	return t
}

func getCurrentBranch() string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to get current branch: %v", err)
	}
	return strings.TrimSpace(string(output))
}

func extractTicketID(branch string) string {
	re := regexp.MustCompile(`[A-Z]+-\d+`)
	match := re.FindString(branch)
	return match
}

func pushBranch(branch string) {
	verboseLog("Pushing branch %s to origin", branch)
	cmd := exec.Command("git", "push", "--set-upstream", "origin", branch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to push branch: %v", err)
	}
}

func createPR(branch string) {
	verboseLog("Creating pull request for branch %s", branch)
	cmd := exec.Command("gh", "pr", "create", "--fill", "--head", branch)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to create pull request: %v", err)
	}
}

func moveToState(jiraBaseURL, ticketID, targetState, authHeader string) {
	transitions := getJiraTransitions(jiraBaseURL, ticketID, authHeader)
	var targetID string
	for _, t := range transitions.Transitions {
		if t.Name == targetState {
			targetID = t.ID
			break
		}
	}
	if targetID == "" {
		log.Printf("No transition to '%s' found", targetState)
		return
	}

	body, _ := json.Marshal(map[string]map[string]string{
		"transition": {"id": targetID},
	})

	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/rest/api/3/issue/%s/transitions", jiraBaseURL, ticketID), bytes.NewBuffer(body))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 300 {
		log.Printf("Failed to move ticket: %v", err)
	} else {
		log.Printf("Moved ticket %s to %s", ticketID, targetState)
	}
}
