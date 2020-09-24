package main

import (
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"

	"example.org/spire-kms-plugin/pkg/kms"
)

func main() {
	p := kms.New()

	catalog.PluginMain(
		catalog.MakePlugin("kms", keymanager.PluginServer(p)),
	)
}
