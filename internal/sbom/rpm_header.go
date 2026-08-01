package sbom

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// RPM header tags of interest. See rpmtag.h in the RPM sources.
const (
	rpmTagName      = 1000
	rpmTagVersion   = 1001
	rpmTagRelease   = 1002
	rpmTagEpoch     = 1003
	rpmTagLicense   = 1014
	rpmTagArch      = 1022
	rpmTagSourceRPM = 1044
)

// RPM header data types.
const (
	rpmTypeInt32      = 4
	rpmTypeString     = 6
	rpmTypeStringArr  = 8
	rpmTypeI18NString = 9
)

// rpmHeaderMagic prefixes a header region with a version and reserved bytes.
var rpmHeaderMagic = []byte{0x8e, 0xad, 0xe8, 0x01}

// rpmPackage is the subset of an RPM header this tool records.
type rpmPackage struct {
	Name      string
	Epoch     string // empty when no epoch tag is present
	Version   string
	Release   string
	Arch      string
	License   string
	SourceRPM string
}

// evr returns the RPM version string in [epoch:]version-release form.
func (p rpmPackage) evr() string {
	v := p.Version
	if p.Release != "" {
		v += "-" + p.Release
	}
	if p.Epoch != "" && p.Epoch != "0" {
		v = p.Epoch + ":" + v
	}
	return v
}

type rpmEntry struct {
	tag    int32
	typ    uint32
	offset int32
	count  uint32
}

// parseRPMHeader decodes an RPM header blob (as stored in the rpmdb) into the
// package fields this tool needs. It accepts blobs with or without the leading
// header magic and validates all offsets against the data store bounds.
func parseRPMHeader(blob []byte) (rpmPackage, error) {
	if bytes.HasPrefix(blob, rpmHeaderMagic) {
		if len(blob) < 8 {
			return rpmPackage{}, fmt.Errorf("rpm header: truncated magic")
		}
		blob = blob[8:]
	}
	if len(blob) < 8 {
		return rpmPackage{}, fmt.Errorf("rpm header: too short (%d bytes)", len(blob))
	}
	il := binary.BigEndian.Uint32(blob[0:4]) // index entry count
	dl := binary.BigEndian.Uint32(blob[4:8]) // data store length
	indexStart := 8
	dataStart := indexStart + int(il)*16
	if il == 0 || il > 1<<20 || dataStart < indexStart {
		return rpmPackage{}, fmt.Errorf("rpm header: implausible index count %d", il)
	}
	if len(blob) < dataStart+int(dl) {
		return rpmPackage{}, fmt.Errorf("rpm header: blob shorter than declared (%d < %d)", len(blob), dataStart+int(dl))
	}
	data := blob[dataStart : dataStart+int(dl)]

	entries := make(map[int32]rpmEntry, il)
	for i := 0; i < int(il); i++ {
		off := indexStart + i*16
		e := rpmEntry{
			tag:    int32(binary.BigEndian.Uint32(blob[off : off+4])),
			typ:    binary.BigEndian.Uint32(blob[off+4 : off+8]),
			offset: int32(binary.BigEndian.Uint32(blob[off+8 : off+12])),
			count:  binary.BigEndian.Uint32(blob[off+12 : off+16]),
		}
		entries[e.tag] = e
	}

	getString := func(tag int32) string {
		e, ok := entries[tag]
		if !ok {
			return ""
		}
		if e.typ != rpmTypeString && e.typ != rpmTypeI18NString && e.typ != rpmTypeStringArr {
			return ""
		}
		if e.offset < 0 || int(e.offset) >= len(data) {
			return ""
		}
		s := data[e.offset:]
		if i := bytes.IndexByte(s, 0); i >= 0 {
			return string(s[:i])
		}
		return string(s)
	}
	getInt32 := func(tag int32) (string, bool) {
		e, ok := entries[tag]
		if !ok || e.typ != rpmTypeInt32 {
			return "", false
		}
		if e.offset < 0 || int(e.offset)+4 > len(data) {
			return "", false
		}
		return fmt.Sprintf("%d", binary.BigEndian.Uint32(data[e.offset:e.offset+4])), true
	}

	pkg := rpmPackage{
		Name:      getString(rpmTagName),
		Version:   getString(rpmTagVersion),
		Release:   getString(rpmTagRelease),
		Arch:      getString(rpmTagArch),
		License:   getString(rpmTagLicense),
		SourceRPM: getString(rpmTagSourceRPM),
	}
	if ep, ok := getInt32(rpmTagEpoch); ok {
		pkg.Epoch = ep
	}
	if pkg.Name == "" {
		return rpmPackage{}, fmt.Errorf("rpm header: missing NAME tag")
	}
	return pkg, nil
}
