package main

import (
	"example.org/spire-kms-plugin/pkg/kms"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

func main() {
	p := kms.New()

	catalog.PluginMain(
		catalog.MakePlugin("kms", keymanager.PluginServer(p)),
	)
}
