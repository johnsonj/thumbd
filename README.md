# thumbd

`thumbd` is a utility for provisioning media and joining it to a single mergerfs filesystem.
It is designed for creating large filesystems based off of cheap USB drives when individual
file durablity is not a priority. 

A set of rules to detect dirves is specified in the config file. Matching drives are repartitioned,
formatted, setup with specified directories, and put into the target MergerFS filesystem.
Filesystem labels are used to prevent re-provisioning existing devices. 

This tool can be ran manually, as part of a udev rule or periodically as on a cron/systemd timer. 
It attempts to be idempotent but it is a large hammer, use at your own risk. Misconfiguration
could result in the wiping of the root filesystem or other sensitive data.

## Dependencies

- golang 1.16+
- [mergerfs](https://github.com/trapexit/mergerfs) 2.0+
- blkid/wipefs (likely `util-linux` package)
- GNU Parted (likely `parted` package)
- Userspace filesystem utils (e.g. `e2fsprogs`)

## Usage

### Configuration

An [example](./config.example.yaml) configuration file with comments is provided. More detail for
the fields are avaliable as comments inline with the cofig struct. See the [godoc](https://pkg.go.dev/github.com/johnsonj/thumbd)
for more information.

### Quickstart

Setup a basic mergerfs filesystem, download/install thumbd, run thumbd in dry-run to preview which
devices would be pulled into the pool.

```bash
# setup a mergerfs filesystem
mkdir mergerfs-target/
mkdir -p mergerfs-devices/{a,b,c}

mergerfs 'mergerfs-devices/*' mergerfs-target/

go get github.com/johnsonj/thumbd
cp $(go env GOPATH)/src/github.com/johnsonj/thumbd/config.example.yaml config.yaml

# Take a look at config.yaml. The default config will wipe all of your thumbdrives.
$EDITOR config.yaml
$(go env GOPATH)/bin/thumbd -config-file config.yaml -dry-run=true
```

### Install on the host

Download/install thumbd onto the local machine. The next step is to automate the execution (e.g. udev rule, cron/systemd timer)

```bash
go get github.com/johnsonj/thumbd
sudo install -o root -g root -m 755 $(go env GOPATH)/bin/thumbd /usr/bin/thumbd
sudo mkdir -p /etc/thumbd
sudo install -o root -g root -m 644 $(go env GOPATH)/github.com/johnsonj/thumbd/config.example.yaml /etc/thumbd/config.yaml
```

