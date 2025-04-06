// Package util provides util functionalities.
package util

// Intersect returns the intersection of two string slices.
func Intersect(a, b []string) []string {
	m := make(map[string]bool)
	seen := make(map[string]bool)
	res := []string{}

	for _, val := range a {
		m[val] = true
	}

	for _, val := range b {
		if m[val] && !seen[val] {
			res = append(res, val)
			seen[val] = true
		}
	}

	return res
}
