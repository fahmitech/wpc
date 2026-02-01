package compiler

import (
	"fmt"

	"github.com/fahmitech/wpc/pkg/types"
)

func GeoSetName(feed types.GeoFeed) string {
	return fmt.Sprintf("wpc_geo_%s_v%d", feed.Name, feed.IPVersion)
}

