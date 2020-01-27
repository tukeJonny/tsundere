package blacklist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/rakyll/statik/fs"
	"github.com/tukejonny/tsundere/bpf/internal/bpfutil"
	_ "github.com/tukejonny/tsundere/bpf/statik"
)

var (
	ErrLoadBlacklist = errors.New("blacklistをロードできませんでした")
)

type BlacklistKey struct {
	BannedIPv4 uint32
}

type Blacklist struct {
	FD         int
	Collection *ebpf.Collection
	Map        *ebpf.Map
	Path       string
}

func NewBlacklist() (*Blacklist, error) {
	statikFS, err := fs.New()
	if err != nil {
		return nil, err
	}

	fd, err := statikFS.Open("/firewall.o")
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	targetBytes, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	targetReader := bytes.NewReader(targetBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(targetReader)
	if err != nil {
		return nil, err
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  1024 * 10240,
		},
	}

	collection, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, err
	}

	m, ok := collection.Maps["blacklist"]
	if !ok {
		return nil, ErrLoadBlacklist
	}

	return &Blacklist{
		FD:         m.FD(),
		Collection: collection,
		Map:        m,
		Path:       filepath.Join(bpfutil.BpfFsPath, "blacklist"),
	}, nil
}

func (b *Blacklist) BPFProgram(name string) *ebpf.Program {
	return b.Collection.Programs[name]
}

func (b *Blacklist) Get(ip net.IP) (cnt uint32, err error) {
	var (
		ipBinary = binary.BigEndian.Uint32(ip.To4())
		key      = BlacklistKey{BannedIPv4: ipBinary}
	)

	err = bpfutil.LookupElement(b.FD, unsafe.Pointer(&key), unsafe.Pointer(&cnt))
	return
}

func (b *Blacklist) Set(ip net.IP) error {
	var (
		ipBinary   = binary.BigEndian.Uint32(ip.To4())
		key        = BlacklistKey{BannedIPv4: ipBinary}
		initialCnt uint32
	)

	return bpfutil.UpdateElement(b.FD, unsafe.Pointer(&key), unsafe.Pointer(&initialCnt), bpfutil.BPF_ANY)
}

func (b *Blacklist) Delete(ip net.IP) error {
	var (
		ipBinary = binary.BigEndian.Uint32(ip.To4())
		key      = BlacklistKey{BannedIPv4: ipBinary}
	)

	return bpfutil.DeleteElement(b.FD, unsafe.Pointer(&key))
}

func (b *Blacklist) List() (map[string]uint32, error) {
	blacklists := map[string]uint32{}

	var key, nextKey BlacklistKey
	for {
		err := bpfutil.GetNextKey(b.FD, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			break
		}

		var entry uint32
		err = bpfutil.LookupElement(b.FD, unsafe.Pointer(&nextKey), unsafe.Pointer(&entry))
		if err != nil {
			return nil, fmt.Errorf("unable to lookup blacklist map: %s", err.Error())
		}

		bannedIPv4 := make(net.IP, 4)
		binary.BigEndian.PutUint32(bannedIPv4, nextKey.BannedIPv4)

		blacklists[bannedIPv4.String()] = entry
		key = nextKey
	}

	return blacklists, nil
}

func (b *Blacklist) Pin() error {
	return bpfutil.ObjPin(b.FD, b.Path)
}

func (b *Blacklist) Unpin() error {
	return os.Remove(b.Path)
}

func (b *Blacklist) Close() {
	b.Collection.Close()
}
