// thumbd is a utility for provisioning media and joining it to a single mergerfs filesystem.
// It is designed for creating large filesystems based off of cheap USB drives.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v2"
)

// Config specifies the options for running thumbd
type Config struct {
	// PoolName is the name used to identify the pool
	// [Optional] defaults to thumbd
	PoolName string `yaml:"poolName,omitempty"`

	// Accept specifies a list of rules to include devices in the pool
	Accept []DeviceRule `yaml:"accept,omitempty"`
	// Deny specifies a list of rules to exclude devices from the pool
	Deny []DeviceRule `yaml:"deny,omitempty"`

	// DeviceSpec specifies the desired configuration of a member of the pool
	DeviceSpec DeviceSpec `yaml:"deviceSpec,omitempty"`
	// PoolSpec specifies the desired merged pool configuration
	PoolSpec PoolSpec `yaml:"poolSpec,omitempty"`
}

type DeviceRule struct {
	// Device path (/sys/devices/...) contains this string
	PathContains string `yaml:"pathContains,omitempty"`

	// Vendor name contains this string
	VendorContains string `yaml:"vendorContains,omitempty"`
}

type DeviceSpec struct {
	// Filesystem specifies the target filesystem for the pooled device
	// Eg: exfat, ext4 (tested: exfat, ext4)
	// [Optional] defaults to ext4
	Filesystem string `yaml:"filesystem,omitempty"`
	// MKFSOptions specifies additional parameters to pass to the mkfs command (e.g. fs tuning)
	// [Optional]
	MKFSOptions []string `yaml:"mkfsOptions,omitempty"`
	// Disklabel specifies the target disk label for the pool device
	// Eg: msdos, gpt - more info: https://www.gnu.org/software/parted/manual/html_node/mklabel.html
	// [Optional] defaults to msdos
	DiskLabel string `yaml:"diskLabel,omitempty"`
}

type PoolSpec struct {
	// DeviceMountPath is a path on the local system that will be used to mount the drives
	DeviceMountPath string `yaml:"deviceMountPath,omitempty"`
	// MergerFSMountPath is a path on the local system to the MergerFS mount point
	MergerFSMountPath string `yaml:"mergerFSMountPath,omitempty"`
	// Directories specifies a list of directories that will be created on the target filesystem
	Directories []Directory
}

type Directory struct {
	// Name of the directory relative to the pooled filesystem
	Name string
	// User owner of the directory
	User string
	// Group owner of the directory
	Group string
}

var DefaultConfig = Config{
	PoolName:   "thumbd",
	Accept:     []DeviceRule{},
	Deny:       []DeviceRule{},
	DeviceSpec: DeviceSpec{Filesystem: "ext4", DiskLabel: "msdos"},
	PoolSpec: PoolSpec{
		DeviceMountPath:   "",
		MergerFSMountPath: "",
		Directories:       []Directory{},
	},
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
		log.Printf("Loading config from file %s", *configFile)
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

	changed, err := provisionDevices(devices, config.PoolName, config.DeviceSpec)
	if err != nil {
		log.Fatalf("Provisioning devices: %v", err)
	}
	if changed {
		devices, err = getDevices(config.Accept, config.Deny)
		if err != nil {
			log.Fatalf("Rediscovering devices: %v", err)
		}
	}

	err = mountAndMerge(config.PoolName, config.PoolSpec, devices)
	if err != nil {
		log.Fatalf("Mounting devices: %v", err)
	}

	log.Printf("thumbd completed successfully")
}

// BlockDevice describes a blcok device on the system (e.g. harddrive)
type BlockDevice struct {
	Path        string    // e.g.: /sys/devices/pci0000:00/0000:00:1d.7/usb2/2-4/2-4:1.0/host7/target7:0:0/7:0:0:0
	DevicePath  string    // e.g.: /dev/sdi
	BlockDevice string    // e.g.: sdi
	Vendor      string    // e.g.: Kingstron
	Model       string    // e.g.: DataTraveler 3.0
	SizeBytes   SizeBytes // size in bytes

	Partitions []Partition
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
	Label      string
	Type       string // eg: exfat
	DevicePath string // eg: /dev/sdk1
	Blkinfo    map[string]string
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

	log.Printf("Discovered %d devices", len(devices))
	return devices, nil
}

func buildMeta(blockDevice string) (BlockDevice, error) {
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

func ioctlGetUint64(fd int, req uint) (uint64, error) {
	var value uint64
	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&value)))
	if err != 0 {
		return 0, err
	}
	return value, nil
}

func ioctlGetStrings(fd int, req uint, input string) ([]string, error) {
	b := make([]byte, 4096)
	for i := 0; i < len(input); i++ {
		b[i] = input[i]
	}
	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&b[0])))
	if err != 0 {
		return nil, err
	}

	return nullTermToStrings(b), nil
}

func ioctlGetString(fd int, req uint, input string) (string, error) {
	a, err := ioctlGetStrings(fd, req, input)
	if err != nil {
		return "", err
	}
	if len(a) > 1 {
		return "", fmt.Errorf("unexpected number of strings returned")
	}
	if len(a) == 0 {
		return "", nil
	}
	return a[0], nil
}

func nullTermToStrings(b []byte) (s []string) {
	for {
		i := bytes.IndexByte(b, '\x00')
		if i == -1 {
			break
		}
		if i != 0 {
			s = append(s, string(b[0:i]))
		}
		b = b[i+1:]
	}
	return s
}

func (bd *BlockDevice) loadPartitions() error {
	partPaths, err := filepath.Glob(filepath.Join("/sys/block/", bd.BlockDevice, bd.BlockDevice+"*"))
	if err != nil {
		return fmt.Errorf("discovering partitions: %w", err)
	}

	var parts []Partition
	for _, p := range partPaths {
		info, err := blkid(filepath.Base(p))
		if err != nil {
			return fmt.Errorf("discovering partition %q: %w", p, err)
		}

		parts = append(parts, Partition{
			Blkinfo:    info,
			Label:      info["LABEL"],
			Type:       info["TYPE"],
			DevicePath: filepath.Join("/dev", filepath.Base(p)),
		})
	}

	bd.Partitions = parts
	return nil
}

func blkid(name string) (map[string]string, error) {
	fullName := filepath.Join("/dev", name)
	res, err := runCommand("blkid", fullName)
	if err != nil {
		return nil, err
	}
	// TODO: will break if there's a space in a key-value paor
	kvs := strings.Split(strings.TrimPrefix(res, fullName+":"), " ")
	output := map[string]string{}
	for _, kv := range kvs {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			continue
		}
		output[parts[0]] = strings.TrimPrefix(strings.TrimSuffix(parts[1], ""), "")
	}
	return output, nil
}

func runCommand(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	stdout := bytes.Buffer{}
	c.Stdout = io.MultiWriter(os.Stdout, &stdout)
	c.Stderr = os.Stderr

	err := c.Run()
	if err != nil {
		return "", err
	}
	return stdout.String(), nil
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

func provisionDevices(bds []BlockDevice, poolName string, spec DeviceSpec) (bool, error) {
	changed := false
Device:
	for _, bd := range bds {
		for _, parts := range bd.Partitions {
			if strings.Contains(parts.Label, poolName) {
				log.Printf("Skipping %q, already provisioned", bd.BlockDevice)
				continue Device
			}
		}
		if err := provision(bd, poolName, spec); err != nil {
			log.Printf("Error provisioning %q: %v", bd.BlockDevice, err)
			continue
		}
		changed = true
	}
	return changed, nil
}

func provision(bd BlockDevice, poolName string, spec DeviceSpec) error {
	log.Printf("Provisioning %q", bd.BlockDevice)
	part := bd.DevicePath + "1"

	for _, p := range bd.Partitions {
		runCommand("umount", p.DevicePath)
	}

	cmds := [][]string{
		{"wipefs", "-a", bd.DevicePath},
		{"parted", "-a", "optimal", bd.DevicePath, "mklabel", spec.DiskLabel},
		{"parted", "-a", "optimal", bd.DevicePath, "mkpart", "primary", "0%", "100%"},
	}

	if strings.Contains(spec.Filesystem, "ext") {
		mkfsCmd := []string{"mkfs", "-t", spec.Filesystem, "-F"}
		mkfsCmd = append(mkfsCmd, spec.MKFSOptions...)
		mkfsCmd = append(mkfsCmd, part)

		cmds = append(cmds, mkfsCmd, []string{"e2label", part, poolName})
	} else {
		log.Printf("Danger, this filesystem is untested")
		cmds = append(cmds, []string{"mkfs", "-t", spec.Filesystem, "-L", poolName, part})
	}

	for _, cmd := range cmds {
		_, err := runCommand(cmd[0], cmd[1:]...)
		if err != nil {
			return fmt.Errorf("running %v: %w", cmd, err)
		}
	}

	return nil
}

/*
valid keys for mergefs 2.32.4:
	"async_read" "auto_cache" "branches" "cache.attr" "cache.entry" "cache.files" "cache.negative_entry" "cache.readdir" "cache.statfs" "cache.symlinks" "cache.writeback" "category.action"
	"category.create" "category.search" "direct_io" "dropcacheonclose" "fsname" "func.access" "func.chmod" "func.chown" "func.create" "func.getattr" "func.getxattr" "func.link"
	"func.listxattr" "func.mkdir" "func.mknod" "func.open" "func.readlink" "func.removexattr" "func.rename" "func.rmdir" "func.setxattr" "func.symlink" "func.truncate" "func.unlink"
	"func.utimens" "fuse_msg_size" "ignorepponrename" "inodecalc" "kernel_cache" "link_cow" "minfreespace" "mount" "moveonenospc" "nfsopenhack" "nullrw" "pid" "posix_acl" "readdirplus"
	"security_capability" "srcmounts" "statfs" "statfs_ignore" "symlinkify" "symlinkify_timeout" "threads" "version" "xattr"
*/
const (
	MergeFSReadKeys    = 0xD000DF00
	MergeFSReadValue   = 0xD000DF01
	MergeFSSetValue    = 0x5000DF02
	MergeFSGetMetadata = 0xD000DF03
)

func mountAndMerge(poolName string, poolSpec PoolSpec, bds []BlockDevice) error {
	f, err := os.OpenFile(poolSpec.MergerFSMountPath, os.O_RDONLY, os.ModeDir)
	if err != nil {
		return fmt.Errorf("opening mergefs device %q: %w", poolSpec.MergerFSMountPath, err)
	}
	defer f.Close()

	version, err := ioctlGetString(int(f.Fd()), MergeFSReadValue, "version")
	if err != nil {
		return fmt.Errorf("unable to read mergefs version %q: %w", poolSpec.MergerFSMountPath, err)
	}
	branches, err := ioctlGetString(int(f.Fd()), MergeFSReadValue, "branches")
	if err != nil {
		return fmt.Errorf("unable to read mergefs branches %q: %w", poolSpec.MergerFSMountPath, err)
	}
	log.Printf("MergeFS poolName=%q version=%q, branches=%q", poolName, version, branches)
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("reading mountinfo: %w", err)
	}

	// detect unmounted devices
	var parts []Partition
	for _, bd := range bds {
		for _, p := range bd.Partitions {
			if strings.Contains(p.Label, poolName) && !strings.Contains(string(mountInfo), p.DevicePath) {
				parts = append(parts, p)
			}
		}
	}

	for _, p := range parts {
		partName := filepath.Base(p.DevicePath)
		mountPoint := filepath.Join(poolSpec.DeviceMountPath, partName)
		log.Printf("Mounting %q to system (mountPoint=%q)", partName, mountPoint)
		err := os.MkdirAll(mountPoint, os.ModeDir)
		if err != nil {
			return fmt.Errorf("creating mount point %q: %w", mountPoint, err)
		}
		_, err = runCommand("mount", filepath.Join("/dev", partName), mountPoint)
		if err != nil {
			return fmt.Errorf("mounting %q: %v", mountPoint, err)
		}
	}
	// detect unjoined devices
	paths, err := filepath.Glob(filepath.Join(poolSpec.DeviceMountPath, "*"))
	if err != nil {
		return err
	}
	for _, p := range paths {
		if strings.Contains(branches, p) {
			continue
		}
		_, err := ioctlGetStrings(int(f.Fd()), MergeFSSetValue, "branches=+>"+p)
		if err != nil {
			return fmt.Errorf("adding %q to pool: %v", p, err)
		}
		log.Printf("Joined %q to pool %q", p, poolName)
	}

	// provision directories
	for _, p := range paths {
		for _, d := range poolSpec.Directories {
			path := filepath.Join(p, d.Name)
			if _, err := os.Stat(path); err == nil {
				continue
			}
			err := os.MkdirAll(path, os.ModePerm)
			if err != nil {
				return fmt.Errorf("creating directory %q: %w", path, err)
			}

			if d.User == "" && d.Group == "" {
				continue
			}

			u, err := user.Lookup(d.User)
			if err != nil {
				return fmt.Errorf("looking up user %q: %v", d.User, err)
			}
			uid, _ := strconv.Atoi(u.Uid)
			g, err := user.LookupGroup(d.Group)
			if err != nil {
				return fmt.Errorf("looking up group %q: %v", d.User, err)
			}
			gid, _ := strconv.Atoi(g.Gid)
			if err := os.Chown(path, uid, gid); err != nil {
				return fmt.Errorf("changing ownership of %q to %q:%q (%d:%d): %w", path, d.User, d.Group, uid, gid, err)
			}

			log.Printf("Created %q (owner=%s:%s)", path, d.User, d.Group)
		}
	}
	return nil
}
