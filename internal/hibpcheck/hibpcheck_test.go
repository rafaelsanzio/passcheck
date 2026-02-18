package hibpcheck

import (
	"errors"
	"testing"

	"github.com/rafaelsanzio/passcheck/internal/issue"
)

type mockChecker struct {
	checkFunc func(password string) (bool, int, error)
}

func (m *mockChecker) Check(password string) (bool, int, error) {
	return m.checkFunc(password)
}

func TestCheckWith(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		opts        Options
		wantIssues  int
		wantCode    string
	}{
		{
			name:     "breached from result",
			password: "password123",
			opts: Options{
				Result: &Result{Breached: true, Count: 10},
			},
			wantIssues: 1,
			wantCode:   issue.CodeHIBPBreached,
		},
		{
			name:     "breached from checker",
			password: "password123",
			opts: Options{
				Checker: &mockChecker{
					checkFunc: func(pw string) (bool, int, error) {
						return true, 5, nil
					},
				},
			},
			wantIssues: 1,
			wantCode:   issue.CodeHIBPBreached,
		},
		{
			name:     "not breached from checker",
			password: "password123",
			opts: Options{
				Checker: &mockChecker{
					checkFunc: func(pw string) (bool, int, error) {
						return false, 0, nil
					},
				},
			},
			wantIssues: 0,
		},
		{
			name:     "checker error handles gracefully",
			password: "password123",
			opts: Options{
				Checker: &mockChecker{
					checkFunc: func(pw string) (bool, int, error) {
						return false, 0, errors.New("api error")
					},
				},
			},
			wantIssues: 0,
		},
		{
			name:     "breached but count below MinOccurrences",
			password: "password123",
			opts: Options{
				Result:         &Result{Breached: true, Count: 2},
				MinOccurrences: 5,
			},
			wantIssues: 0,
		},
		{
			name:     "breached and count at MinOccurrences",
			password: "password123",
			opts: Options{
				Result:         &Result{Breached: true, Count: 5},
				MinOccurrences: 5,
			},
			wantIssues: 1,
			wantCode:   issue.CodeHIBPBreached,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckWith(tt.password, tt.opts)
			if len(got) != tt.wantIssues {
				t.Errorf("CheckWith() = %d issues, want %d", len(got), tt.wantIssues)
			}
			if tt.wantIssues > 0 && got[0].Code != tt.wantCode {
				t.Errorf("CheckWith() issue code = %s, want %s", got[0].Code, tt.wantCode)
			}
		})
	}
}
