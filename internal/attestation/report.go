package attestation

import (
	"fmt"
	"os"
	"time"
)

func summarize(events []Event, now time.Time) Report {
	r := Report{Status: "not_configured", Scope: "OS user; all configured repositories", History: []Event{}, Limitation: limitation}
	for _, e := range events {
		if e.Kind != "checked" {
			r.History = append(r.History, e)
		}
	}
	if len(events) > 0 {
		last := events[len(events)-1]
		r.State = &last.State
		r.Head = last.Hash
		r.Status = last.State.Configuration
		if !last.State.Enabled {
			r.Status = "disabled"
		} else if now.Sub(last.State.LastObserved) > MaxObservationGap || now.Before(last.State.LastObserved) {
			r.Status = "unknown"
		}
	}
	return r
}

// Current never creates a store. Disabled/unconfigured installations do no observation work.
func Current(observe Observer, reconcile bool) Report {
	path, err := DefaultPath()
	if err == nil {
		_, err = os.Stat(path)
		if os.IsNotExist(err) {
			return summarize(nil, time.Now())
		}
	}
	if err != nil {
		return Failure(err)
	}
	s, err := Open(path)
	if err != nil {
		return Failure(err)
	}
	defer s.Close()
	var r Report
	if reconcile {
		r, err = s.Apply("check", nil, "", time.Now(), observe)
	} else {
		r, err = s.Read(time.Now())
	}
	if err != nil {
		return Failure(err)
	}
	return r
}
func Failure(err error) Report {
	return Report{Status: "unknown", Scope: "OS user", History: []Event{}, Error: err.Error(), Limitation: limitation}
}
func (r Report) Summary() string {
	return fmt.Sprintf("%s; %d historical transitions; configuration only, not delivery", r.Status, len(r.History))
}
