package api

import (
	"sort"

	"github.com/patsypppe/sentinel/fleet/internal/posture"
)

func sortWaivers(w []posture.ExpiringWaiver) {
	sort.SliceStable(w, func(i, j int) bool {
		if w[i].StillFailing != w[j].StillFailing {
			return w[i].StillFailing
		}
		if !w[i].ExpiresAt.Equal(w[j].ExpiresAt) {
			return w[i].ExpiresAt.Before(w[j].ExpiresAt)
		}
		return w[i].Target < w[j].Target
	})
}
