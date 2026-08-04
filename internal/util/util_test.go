// Package util provides util functionalities.
package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntersectReturnsCommonDedupedElements(t *testing.T) {
	result := Intersect([]string{"a", "b", "c"}, []string{"b", "c", "c", "d"})

	assert.Equal(t, []string{"b", "c"}, result)
}

func TestIntersectReturnsEmptyWhenNoOverlap(t *testing.T) {
	result := Intersect([]string{"a"}, []string{"b"})

	assert.Empty(t, result)
}

func TestIntersectReturnsEmptyWhenEitherInputEmpty(t *testing.T) {
	assert.Empty(t, Intersect(nil, []string{"a"}))
	assert.Empty(t, Intersect([]string{"a"}, nil))
}
