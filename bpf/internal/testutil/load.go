package testutil

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func LoadObject(t *testing.T, path string) *ebpf.Collection {
	spec, err := ebpf.LoadCollectionSpec(path)
	assert.NoError(t, err)

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  1024 * 10240,
		},
	}

	collection, err := ebpf.NewCollectionWithOptions(spec, opts)
	assert.NoError(t, err)

	return collection
}
