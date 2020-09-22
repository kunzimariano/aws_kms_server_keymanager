package main

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server"
)

func main() {
	_ = server.New(server.Config{})
	catalog.PluginMain(catalog.MakePlugin("", nil))
}
