package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/partition"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

type Config struct {
	// PoolName is the name used to identify the thumbd pool
	// [Optional] this will be defaulted
	PoolName string

	// Accept specifies a list of rules to include devices in the pool
	Accept []DeviceRule
	// Deny specifies a list of rules to exclude devices from the pool
	Deny []DeviceRule

	// DeviceSpec specifies the desired configuration of a member of the pool
	DeviceSpec DeviceSpec
}

type DeviceRule struct {
	// Device path (/sys/devices/...) contains this string
	PathContains string

	// Vendor name contains this string
	VendorContains string
}

type DeviceSpec struct {
	Filesystem string // Valid: fat32, iso9660, squashfs
}

var DefaultConfig = Config{
	PoolName: "thumbd",
	Accept:   []DeviceRule{{PathContains: "usb2"}},
	Deny:     []DeviceRule{{VendorContains: "Kings"}},
}

var configFile = flag.String("config-file", "/etc/thumbd/config.yaml", "Path to the config file for this instance of thumbd")

func main() {
	config := DefaultConfig
	fileBytes, err := ioutil.ReadFile(*configFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("Warning: config-file %s can not be opened, using defualt settings", *configFile)
		} else {
			log.Fatalf("Failed to open config-file %s: %v", *configFile, err)
		}
	}
	if len(fileBytes) != 0 {
		err := yaml.Unmarshal(fileBytes, &config)
		if err != nil {
			log.Fatalf("Failed to unmarshal config-file %s: %v", *configFile, err)
		}
	}
	log.Printf("Using config: %+v", config)

	devices, err := getDevices(config.Accept, config.Deny)
	if err != nil {
		log.Fatalf("Discovering devices: %v", err)
	}
	log.Printf("Devices: %+v", devices)

	/*
		- initialize device (if appropriate)
		 -> https://github.com/diskfs/go-diskfs ?
		- mount device
		- add to mergefs
	*/
}

// BlockDevice describes a blcok device on the system (e.g. harddrive)
type BlockDevice struct {
	Name        string
	Path        string    // e.g.: /sys/devices/pci0000:00/0000:00:1d.7/usb2/2-4/2-4:1.0/host7/target7:0:0/7:0:0:0
	DevicePath  string    // e.g.: /dev/sdi
	BlockDevice string    // e.g.: sdi
	Vendor      string    // e.g.: Kingstron
	Model       string    // e.g.: DataTraveler 3.0
	SizeBytes   SizeBytes // size in bytes

	Partitions     []Partition
	PartitionTable partition.Table
}

type SizeBytes uint64

func (b SizeBytes) String() string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

// Parition describes a single parition on a block device
type Partition struct {
	Label string // e.g.: zfs-2562b3b3163d0b6f
	Type  filesystem.Type
}

func getDevices(acceptRules, denyRules []DeviceRule) ([]BlockDevice, error) {
	log.Printf("Discovering devices")

	dir, err := ioutil.ReadDir("/sys/block")
	if err != nil {
		return nil, fmt.Errorf("reading /sys/block: %w", err)
	}

	var devices []BlockDevice
	for _, f := range dir {
		device, err := buildMeta(f.Name())
		if err != nil {
			log.Printf("Warning, skipping block device due to error: %v", err)
			continue
		}
		accept := match(device, acceptRules)
		if !accept {
			continue
		}

		deny := match(device, denyRules)
		if deny {
			log.Printf("Device %s matched accept and deny rule and will be skipped", f.Name())
			continue
		}

		if err := device.loadPartitions(); err != nil {
			log.Printf("Warning, error reading partition data of %s: %v", f.Name(), err)
		}

		devices = append(devices, device)
	}

	log.Printf("discovered %d devices", len(devices))
	return devices, nil
}

func buildMeta(blockDevice string) (BlockDevice, error) {
	log.Printf("Building %q", blockDevice)
	device := BlockDevice{
		BlockDevice: blockDevice,
		DevicePath:  filepath.Join("/dev", blockDevice),
	}

	fullBlockPath, err := filepath.EvalSymlinks(filepath.Join("/sys/block", blockDevice))
	if err != nil {
		return device, fmt.Errorf("evaluating block device symlink %s: %w", blockDevice, err)
	}
	device.Path = strings.TrimSuffix(fullBlockPath, filepath.Join("block", blockDevice))

	model, err := os.ReadFile(filepath.Join(device.Path, "model"))
	if err != nil {
		log.Printf("Warning: failed to resolve model for block device %s", blockDevice)
	} else {
		device.Model = string(model)
	}

	vendor, err := os.ReadFile(filepath.Join(device.Path, "vendor"))
	if err != nil {
		log.Printf("Warning: failed to resolve vendor for block device %s", blockDevice)
	} else {
		device.Vendor = string(vendor)
	}

	f, err := os.OpenFile(device.DevicePath, os.O_RDONLY, os.ModeDevice)
	if err != nil {
		return device, nil
	}
	defer f.Close()

	size, err := ioctlGetUint64(int(f.Fd()), unix.BLKGETSIZE64)
	if err != nil {
		log.Printf("Warning: failed to read size for block device %s: %v", blockDevice, err)
	} else {
		device.SizeBytes = SizeBytes(size)
	}

	return device, nil
}

// x/sys/unit does not have a uint64 version
func ioctlGetUint64(fd int, req uint) (uint64, error) {
	var value uint64
	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&value)))
	if err != 0 {
		return 0, err
	}
	return value, nil
}

func (bd *BlockDevice) loadPartitions() error {
	return fmt.Errorf("NYI")
	disk, err := diskfs.OpenWithMode(filepath.Join("/dev", bd.BlockDevice), diskfs.ReadOnly)
	if err != nil {
		return fmt.Errorf("opening disk: %w", err)
	}

	partt, err := disk.GetPartitionTable()
	if err != nil {
		return fmt.Errorf("reading partition table: %w", err)
	}

	bd.PartitionTable = partt

	for i := range partt.GetPartitions() {
		fs, err := disk.GetFilesystem(i + 1)
		if err != nil {
			continue
		}
		bd.Partitions = append(bd.Partitions, Partition{Label: fs.Label(), Type: fs.Type()})
	}

	return nil
}

func match(device BlockDevice, rules []DeviceRule) bool {
	for _, r := range rules {
		if len(r.PathContains) != 0 && strings.Contains(device.Path, r.PathContains) {
			return true
		}
		if len(r.VendorContains) != 0 && strings.Contains(device.Vendor, r.VendorContains) {
			return true
		}
	}
	return false
}
