package bpfutil

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// See https://github.com/cilium/cilium/blob/master/pkg/bpf/bpf.go

// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
const (
	BPF_MAP_TYPE_UNSPEC = iota
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
	BPF_MAP_TYPE_CGROUP_ARRAY
	BPF_MAP_TYPE_LRU_HASH
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	BPF_MAP_TYPE_LPM_TRIE
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	BPF_MAP_TYPE_HASH_OF_MAPS
	BPF_MAP_TYPE_DEVMAP
	BPF_MAP_TYPE_SOCKMAP
	BPF_MAP_TYPE_CPUMAP
	BPF_MAP_TYPE_XSKMAP
	BPF_MAP_TYPE_SOCKHASH
	BPF_MAP_TYPE_CGROUP_STORAGE
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
)

// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
const (
	BPF_MAP_CREATE = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
)

// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
const (
	BPF_ANY = iota
	BPF_NOEXIST
	BPF_EXIST
)

// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
const (
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
	BPF_F_NUMA_NODE     = 1 << 2
)

// Fd represents HASH_OF_MAPS value.
type Fd struct{ Fd uint32 }

// This struct must be in sync with union bpf_attr's anonymous struct
// used by the BPF_MAP_CREATE command
type bpfAttrCreateMap struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
	innerID    uint32
}

// CreateMap creates a Map of type mapType, with key size keySize, a value size of
// valueSize and the maximum amount of entries of maxEntries.
// mapType should be one of the bpf_map_type in "uapi/linux/bpf.h"
// When mapType is the type HASH_OF_MAPS an innerID is required to point at a
// map fd which has the same type/keySize/valueSize/maxEntries as expected map
// entries. For all other mapTypes innerID is ignored and should be zeroed.
func CreateMap(mapType int, keySize, valueSize, maxEntries, flags, innerID uint32) (int, error) {
	uba := bpfAttrCreateMap{
		uint32(mapType),
		keySize,
		valueSize,
		maxEntries,
		flags,
		innerID,
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if err != 0 {
		return 0, fmt.Errorf("Unable to create map: %s", err)
	}
	return int(ret), nil
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_MAP_*_ELEM commands
type bpfAttrMapOpElem struct {
	mapFd uint32
	pad0  [4]byte
	key   uint64
	value uint64 // union: value or next_key
	flags uint64
}

// UpdateElement updates the map in fd with the given value in the given key.
// The flags can have the following values:
// bpf.BPF_ANY to create new element or update existing;
// bpf.BPF_NOEXIST to create new element if it didn't exist;
// bpf.BPF_EXIST to update existing element.
func UpdateElement(fd int, key, value unsafe.Pointer, flags uint64) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: uint64(flags),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to update element for map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
func LookupElement(fd int, key, value unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to lookup element in map with file descriptor %d: %s", fd, err)
	}

	return nil
}

func deleteElement(fd int, key unsafe.Pointer) (uintptr, syscall.Errno) {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	return ret, err
}

// DeleteElement deletes the map element with the given key.
func DeleteElement(fd int, key unsafe.Pointer) error {
	ret, err := deleteElement(fd, key)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to delete element from map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// GetNextKey stores, in nextKey, the next key after the key of the map in fd.
func GetNextKey(fd int, key, nextKey unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(nextKey)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to get next key from map with file descriptor %d: %s", fd, err)
	}

	return nil
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_PROG_TEST_RUN commands
type bpfAttrTest struct {
	progFd      uint32
	retVal      uint32
	dataSizeIn  uint32
	dataSizeOut uint32
	dataIn      uint64
	dataOut     uint64
	repeat      uint32
	duration    uint32
}

func ProgTestRun(fd int, repeat int, in, out []byte) (int, int, int, error) {
	uba := bpfAttrTest{
		progFd:     uint32(fd),
		dataSizeIn: uint32(len(in)),
		dataIn:     uint64(uintptr(unsafe.Pointer(&in[0]))),
		repeat:     uint32(repeat),
	}
	if out != nil {
		uba.dataOut = uint64(uintptr(unsafe.Pointer(&out[0])))
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_PROG_TEST_RUN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if ret != 0 || err != 0 {
		return int(uba.retVal), int(uba.duration), int(uba.dataSizeOut), fmt.Errorf("bpf_prog_test_run failed: %d: %s", ret, err)
	}
	return int(uba.retVal), int(uba.duration), int(uba.dataSizeOut), nil
}

const BpfFsPath = "/sys/fs/bpf"

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_OBJ_*_ commands
type bpfAttrObjOp struct {
	pathname uint64
	fd       uint32
	pad0     [4]byte
}

// ObjPin stores the map's fd in pathname.
func ObjPin(fd int, pathname string) error {
	pathStr := C.CString(pathname)
	defer C.free(unsafe.Pointer(pathStr))
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
		fd:       uint32(fd),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_PIN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to pin object with file descriptor %d to %s: %s", fd, pathname, err)
	}

	return nil
}

// ObjGet reads the pathname and returns the map's fd read.
func ObjGet(pathname string) (int, error) {
	pathStr := C.CString(pathname)
	defer C.free(unsafe.Pointer(pathStr))
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
	}

	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if fd == 0 || err != 0 {
		return 0, &os.PathError{
			Op:   "Unable to get object",
			Err:  err,
			Path: pathname,
		}
	}

	return int(fd), nil
}
