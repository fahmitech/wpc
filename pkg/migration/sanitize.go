package migration

import (
	"fmt"
	"strings"

	"github.com/fahmitech/wpc/pkg/utils"
)

func SafePeerName(legacy string) (string, error) {
	base := strings.TrimSpace(legacy)
	if base == "" {
		return "", fmt.Errorf("empty legacy identity")
	}

	var b strings.Builder
	b.Grow(len(base) + len("peer_"))
	b.WriteString("peer_")

	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}

	name := strings.Trim(b.String(), "_")
	if name == "peer" || name == "peer_" {
		return "", fmt.Errorf("legacy identity %q produced empty safe name", legacy)
	}

	if err := utils.ValidateString(name); err != nil {
		return "", fmt.Errorf("legacy identity %q produced invalid name %q: %w", legacy, name, err)
	}

	return name, nil
}
