// Code generated for package logschema by go-bindata DO NOT EDIT. (@generated)
// sources:
// schema.json
package logschema

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _schemaJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x1a\x7b\x6f\x14\xb7\xf3\xff\x7c\x0a\x6b\xc9\x4f\xfa\x15\x2e\x5c\xd2\x94\x56\x44\xaa\x2a\x48\xa1\x20\xf1\x88\x48\x01\x95\xdc\x25\x72\x76\x67\xef\x4c\xbd\xf6\xd6\xf6\x26\x39\xd0\x7d\xf7\x6a\xdf\x6b\xaf\xbd\x8f\x5c\x42\x55\xca\x1f\x90\x3b\x7b\x66\x3c\x33\x9e\xa7\xe7\x3e\x6f\x21\xe4\x6d\x4b\x7f\x09\x11\xf6\x0e\x90\xb7\x54\x2a\x3e\x98\x4e\x3f\x4a\xce\x76\xf2\xd5\xfb\x5c\x2c\xa6\x81\xc0\xa1\xda\xd9\xfd\x69\x9a\xaf\xdd\xf1\x26\x29\x9e\x22\x8a\x42\x8a\x75\x84\x99\x5a\x82\x40\x94\x2f\x50\x41\x2b\x03\xd8\x26\x41\x49\x54\x1e\x4c\xa7\x22\x61\x71\x0e\x79\x9f\xf0\x82\x94\x9c\x52\xbe\x90\x31\xf8\xd3\x8b\xdd\x02\x49\x40\x98\x62\xdd\x99\x06\x10\x12\x46\x14\xe1\x4c\x16\xd0\xc7\x31\xf8\x39\x54\x63\xcf\x3b\x40\xa9\x18\x08\x79\x0d\xa0\x72\x2d\x65\x73\x15\x67\x5c\xf2\xf3\x8f\xe0\xab\x0c\x3d\x5b\x8f\x05\x8f\x41\x28\x02\xb2\x01\x8d\x90\x77\x01\x42\x12\xce\xb4\x45\x84\x3c\x9f\x33\xa9\xbc\x03\xb4\x5b\x2d\xae\x27\x35\x52\xa5\x42\x0d\xa7\x3c\x5a\x2a\x41\xd8\xc2\x9b\x34\xf7\x22\xc2\x5e\x00\x5b\xa8\xa5\x77\x80\xf6\xb5\x9d\x18\x2b\x05\x22\x65\xc0\x3b\x3d\x79\xb4\xf3\x61\x9e\xfe\x87\x77\x3e\xed\xee\x3c\x9c\xdf\xfb\xff\x6c\x76\xbf\xb5\xf8\xdd\x2f\xdb\x9e\x95\xad\x00\xa4\x2f\x48\xac\x2c\xf2\x18\xbc\x59\xd1\x05\x84\x20\x80\xf9\xf0\xf6\xcd\x8b\x31\xb2\x85\x5c\x44\x38\x55\x96\x97\x08\x62\x27\x1d\x63\x21\x41\xb8\x88\x1a\x77\x95\x2b\x0c\x5f\x1d\x35\xaf\x6c\xcf\x54\x67\xc7\xae\xe3\xae\xf3\x8b\x95\x17\xad\x45\x84\x3c\xce\xe0\x75\x6a\x88\x27\xc6\x06\x6a\x81\x66\xe0\x76\xb3\xcd\xa5\x3c\x3c\x7e\xf7\x9e\xa8\xe5\x33\xc0\x01\x08\xaf\x85\xbd\x9e\xdc\xd8\x11\x3c\x51\xce\x53\x8c\x95\xf9\x56\x07\x0f\x5e\x88\xa5\x8a\xb0\xf2\x97\x36\xd5\x74\x31\xf2\x14\x4b\xf5\x32\x43\xec\xa4\x2f\x60\x01\x57\x63\x69\xbf\x49\x91\x06\x10\x67\x58\x91\x0b\x18\x4b\xfd\x55\x8e\xb5\xe5\x52\xda\xda\x6a\xc7\x21\x01\x1a\x98\x56\xe5\x38\x27\xb7\xea\xa7\x39\x86\xc3\x5f\xdb\x61\xad\xd8\xea\x72\x8d\x22\x62\x1c\x75\x58\x79\x3b\x92\x6c\x0f\x57\xd0\x05\xa6\x09\x64\x71\xd5\xad\x1d\x8d\x21\x1c\x04\x19\x2a\xa6\x1a\x4f\x21\xa6\x12\xb6\x4c\xf4\x0a\xd5\x13\xf0\x57\x42\x04\xa4\x59\xe3\xa4\x8a\xc3\x93\x4a\xc9\xb9\xc9\x16\xe0\x9e\xa6\x4d\x4b\xbc\xc7\x42\xe0\x55\x1d\xee\x23\xc2\x9e\x2b\x88\xb4\xd8\xe0\x91\x62\xa5\x11\xfe\xed\x1a\xc8\x38\x68\x6a\x60\xad\xf1\x52\x6f\x37\x18\xc1\x94\x1a\x11\x64\xf8\x85\x76\xdc\x24\xc3\x91\xd5\xb6\x5d\x01\xbd\x75\x3b\xba\xa2\x9d\x74\xce\x39\xa7\x80\x59\x37\xa1\x02\x78\xa0\x1d\xa5\xd0\xc7\x7e\xcb\x8c\x0c\x9a\xee\xa4\xd5\x2f\xa7\xd3\x22\x35\xd3\xca\x54\x38\x29\x48\xcd\x6d\x9e\x38\xc0\x9b\x2d\x4e\x51\x1e\xaf\x1b\x6a\x0d\xd8\x30\x8e\x76\x7a\x19\x70\x64\x2e\xb2\x71\xe6\x28\xa6\x73\x63\xdb\x84\x42\xe6\x56\x9b\x10\x90\x3e\xa6\x58\x6c\x42\x41\x91\xc8\x54\xfc\x28\x7c\x01\xe1\x90\x7b\xab\xac\xd5\x12\x5c\x8c\xaa\xc7\x03\x96\x44\xda\x6d\xb6\xeb\xa2\xb6\xa3\x1b\x21\x0a\x21\x2f\x2d\xbc\x9b\xdf\x09\xd3\xe0\x43\xca\xb1\xb6\x20\x23\x4c\xa9\x01\x74\x4e\x16\xe6\x4a\xe1\xc9\x8d\xa5\x54\x85\x52\xe1\x28\xf6\xf4\x72\xcf\xb3\x6a\xa2\x61\x35\x1b\x14\xd6\x96\x58\x51\x55\xd5\x25\x91\xdb\xca\xb1\xdd\xa9\x26\xe3\xcc\x95\x67\x6a\x83\xbf\x2d\xd9\x73\x33\xb0\x8a\x0e\x14\x22\x60\x6a\x98\xec\x1d\x11\xa9\x47\xf0\xf2\x18\x5d\xf2\x86\xa7\xde\xb0\xe8\x5d\xcd\x43\xe9\x4a\xb9\xf1\x57\x46\x5f\x1b\x76\xd3\xec\x4b\x97\xa9\x8d\x7c\x3e\x4a\xf6\x56\xa4\x26\x01\x56\x63\x83\x75\x57\x26\xd7\x8e\xc4\x94\xf2\x4b\x6f\x3e\x38\xd5\xe7\xf0\x1d\x39\xd0\x0c\x20\xc5\xb6\xad\xd6\xa9\x36\xdb\x35\xcf\x90\x6b\xa9\x29\x57\x5d\xeb\x9e\xb1\xbd\x76\xa7\xe2\xde\x40\x3d\x58\x85\x01\xb0\xd5\x08\x0d\x66\xe0\x5f\x95\x02\xad\x01\xba\x51\x18\x0c\xf0\x54\x8b\x1b\x6c\x16\xc0\xba\xde\x10\x08\x0b\x88\x8f\x15\x17\xce\x8e\xa6\x7d\x07\xba\x96\xb4\x1d\xbb\xf2\x1d\x01\xb1\x3a\xdb\xeb\x33\xc6\xca\xf5\x07\x47\xda\x3a\x50\xb4\x03\x8e\x76\x37\x35\x13\xd7\xaa\x23\x88\x96\xa2\x03\x1e\x61\xa2\x65\xf2\x25\x97\x2a\xaf\x67\xeb\xb5\x44\xd0\xe6\xd7\x28\x78\xa0\x15\x0d\x4b\xbc\x67\x7c\xff\xfe\xc1\x8f\x5a\x5d\x72\x29\xcf\xb0\x60\xad\x25\xdf\xe7\x09\x53\x67\x24\x30\x77\x08\x93\x0a\x33\x1f\x2c\x5b\x0a\x6b\x45\x90\x12\xb8\x05\x96\x48\x10\xa6\x08\x10\x61\xa2\x09\xc1\x40\x9d\xe1\x20\x10\xf6\x0a\xa5\x2a\x09\x6f\x2b\x47\xd7\x05\x93\xdd\xca\xe5\x93\x0b\x60\xea\x77\xd2\xea\xcd\xdc\xfd\xd4\xda\xa8\xc7\x9e\x96\xaf\x66\x1a\xba\xfd\x1d\xaa\xaf\x2b\x6a\x05\xad\xea\xb1\xf6\x71\x42\xa8\xda\x21\x0c\x55\x12\xa1\xe2\xb9\xae\x85\xa3\x37\x62\xde\x21\x8f\x22\xde\xc6\x93\x6d\xc4\x2a\x85\x8b\xd0\xdf\xdf\xdf\x7f\x98\xe6\xe7\x84\x91\xab\xf2\xef\x59\x24\xab\x8f\x49\xfd\x91\x65\x1f\x7d\xca\x93\x20\xa4\x58\x34\x5b\x33\xd4\xee\x13\xaf\xaf\x82\xc3\x44\x2a\x1e\x8d\x57\xc0\x23\xe4\xd7\x98\x05\x12\x22\x0c\x49\x25\xc2\x6c\x89\x71\x85\x33\xe0\x16\xa5\xc6\x9b\xee\xff\x4e\xf0\xa3\xf3\xc7\xfe\x61\x10\x3e\x7b\xfe\x31\x7a\x19\x1f\xbf\xbd\x7c\x7f\xb5\xfa\xe3\xd3\x87\x79\x67\x5b\x7c\x7d\x71\x7f\xe3\x88\xe2\x15\x4f\xd4\xcd\x49\xbc\xa8\x48\x0e\x12\xf9\x34\x07\xfe\xd9\xdd\xac\x8f\xab\xda\x26\x9a\xc3\xe8\x91\xa0\x6c\xee\x6e\x2b\x10\x34\x9a\x24\xc3\x85\xb1\x58\x40\xcb\x7d\x87\x8e\x00\xf6\x06\x2b\x20\x3f\x46\x7f\xbd\x28\x85\xb7\xbd\x37\x8f\x2d\x08\x96\x58\x16\x98\xfd\x55\x41\x0d\xeb\x50\x97\x12\x09\x58\xb5\x15\x00\x25\x11\x51\xee\x11\x40\x67\x6b\x30\x49\xe5\x9f\x65\x5a\x40\x46\x35\x18\x40\x88\x13\x9a\x5d\xd5\xc4\x7e\x51\x3e\xa7\x49\xe4\x7e\x60\xb5\x97\x23\xd6\x72\xd0\x55\x8d\x74\xba\xa6\xb3\x04\xb4\x17\x26\xf2\x4f\x12\x1f\x09\x08\x89\xf9\x5c\x7e\x1d\xd3\xd2\x12\x6c\xac\x56\xef\xd2\x8e\xf1\x0b\x6a\xa2\x57\x5a\x25\x48\x74\x1c\x63\xff\x7a\x59\x14\xae\x62\xcc\x82\xd6\x93\x30\x72\x17\x72\x0a\xae\xd4\x51\xe6\x34\x4f\x9a\xb8\x3d\x25\x9d\x63\xe6\x32\xd6\xd3\x4a\x43\xec\xf7\xb3\x7f\xd0\x5b\x7a\x5d\xdc\x78\xd4\xff\xe6\x68\xdf\x1c\xed\x86\x1d\xad\x9e\x29\x8e\xf5\xb0\x7c\x84\xd9\xef\x5f\xb6\x51\xe7\x4d\xde\x8e\x63\xa8\x54\x0e\x59\x8f\x8a\x52\xe9\xbf\x65\xa3\x1b\x79\xeb\xbf\xc9\x7e\x5f\x99\xf3\x68\xcb\x34\xaa\xdf\x46\x2d\x73\x3f\xf7\x8f\x38\x3a\xb8\x69\x4c\xd1\x6f\xcb\x9d\x8a\xd2\xff\xd7\x54\x7f\xb7\x3b\xcc\xde\xdd\x79\x78\x36\xbf\x6b\x1d\x65\xf7\xf5\x47\xee\x97\xb8\x4d\xe7\xda\x93\x2f\x17\x58\xc6\x86\xfd\xaf\x2a\x80\x7c\x25\x41\xc2\x81\x35\xc0\x39\x1d\xe6\xd8\x6e\x65\x0d\x8d\x19\x3f\x5e\x30\xd3\xd0\xf8\xdf\x30\xf4\x19\xcd\x0f\x36\x05\x0f\xa6\xd4\xf8\xa1\x61\xc6\x20\xba\x24\x6a\x89\x62\x8a\x7d\x58\x72\x9a\x96\xa6\x1a\xf8\xb6\xcf\xa3\x62\x68\xe6\xbd\x4c\xa4\x42\x3e\x67\x0a\x13\x86\xb0\x42\x14\xb0\x54\x88\x33\x70\xa3\x37\x9f\x6a\x3e\xcf\x66\xf2\xee\xc9\xe9\x7a\x7e\x2f\xfd\x30\x9b\xad\xfb\x47\xce\xa3\x05\xc9\x5e\x51\xe0\x92\x12\x06\xd2\x2d\xc8\x6b\x46\x57\x28\x9b\x07\x95\xc0\xa9\x38\x6a\x09\x08\x58\xe0\x14\xe0\xf4\xe4\x74\x36\x63\x29\xf7\x4c\xfb\x89\x60\xf1\xa9\x78\x3c\xd8\x4a\xff\xad\xb7\xfe\x0e\x00\x00\xff\xff\x20\x81\x22\xc9\x0d\x2a\x00\x00")

func schemaJsonBytes() ([]byte, error) {
	return bindataRead(
		_schemaJson,
		"schema.json",
	)
}

func schemaJson() (*asset, error) {
	bytes, err := schemaJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "schema.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"schema.json": schemaJson,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"schema.json": {schemaJson, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
