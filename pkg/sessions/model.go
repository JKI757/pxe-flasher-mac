package sessions

import "time"

type SessionEvent struct {
	RunID   string            `json:"run_id"`
	MAC     string            `json:"mac"`
	IP      string            `json:"ip"`
	Type    string            `json:"type"`
	Time    time.Time         `json:"time"`
	Details map[string]string `json:"details,omitempty"`
}
