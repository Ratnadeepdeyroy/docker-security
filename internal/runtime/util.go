package runtime

import "strconv"

// itoa is a terse alias for strconv.Itoa used across rule and metadata code,
// where the integer→string conversion is frequent and incidental to intent.
func itoa(i int) string { return strconv.Itoa(i) }
