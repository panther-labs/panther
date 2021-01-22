// Code generated for package logschema by go-bindata DO NOT EDIT. (@generated)
// sources:
// schema.json
package logschema

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

var _schemaJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x5a\xdf\x73\x13\xb7\x13\x7f\xcf\x5f\xa1\x11\xf9\xbe\x80\x8d\xc3\x37\xa5\x1d\xf2\xd2\x81\x14\x06\x66\x60\xc8\x90\x02\x53\x62\x27\xa3\xdc\xed\xd9\xa2\x3a\xe9\x2a\xe9\x12\x07\xc6\xff\x7b\xe7\x7e\xf9\x24\x9d\x74\xb6\xe3\x98\x4e\x29\x0f\xc0\x59\xda\x5d\xed\xae\x3e\xbb\x5a\xad\xf8\xba\x87\x10\xde\x57\xd1\x0c\x52\x82\x8f\x10\x9e\x69\x9d\x1d\x8d\x46\x9f\x95\xe0\xc3\x6a\xf4\xa1\x90\xd3\x51\x2c\x49\xa2\x87\x07\xbf\x8c\xaa\xb1\x7b\x78\x50\xf0\x69\xaa\x19\x14\x5c\x27\x84\xeb\x19\x48\xc4\xc4\x14\xd5\xb2\x4a\x82\x7d\x1a\x37\x42\xd5\xd1\x68\x24\x73\x9e\x55\x94\x0f\xa9\xa8\x45\xa9\x11\x13\x53\x95\x41\x34\xba\x3a\xa8\x99\x24\x24\x05\xd7\xbd\x51\x0c\x09\xe5\x54\x53\xc1\x55\x4d\x7d\x9a\x41\x54\x51\x19\x73\xf8\x08\x15\x66\x20\x84\x0d\xa2\x66\xac\x50\xf3\x26\x2b\xb5\x14\x97\x9f\x21\xd2\x25\x7b\x39\x9e\x49\x91\x81\xd4\x14\x94\x41\x8d\x10\xbe\x02\xa9\xa8\xe0\xd6\x20\x42\x38\x12\x5c\x69\x7c\x84\x0e\x96\x83\x8b\x41\xcb\xb4\x74\xa1\xc5\xd3\x2c\xad\xb4\xa4\x7c\x8a\x07\xe6\x5c\x4a\xf9\x6b\xe0\x53\x3d\xc3\x47\xe8\xd0\x9a\xc9\x88\xd6\x20\x0b\x05\xf0\xf9\xd9\xd3\xe1\xa7\x49\xf1\x17\x19\x7e\x39\x18\x3e\x99\x3c\xd8\xc7\xde\xf5\x63\x50\x91\xa4\x99\xf6\x28\xee\x28\xe1\x65\x97\x90\x80\x04\x1e\xc1\xfb\x77\xaf\x37\x31\x22\x11\x32\x25\x85\x57\x70\x2e\xa9\x5f\x74\x46\xa4\x02\x19\x12\xea\x6c\x4a\xe5\x19\x32\x3f\x31\xf7\xe6\x91\xeb\xb7\x9e\xd9\xc0\xa6\x56\x3b\xa8\xae\x3a\x83\x08\x61\xc1\xe1\x6d\x81\xb8\x33\x67\x02\x75\x48\x4b\x72\x3f\x3e\x2b\x2b\x8f\x4f\x3f\x7c\xa4\x7a\xf6\x12\x48\x0c\x12\x77\xb8\x17\x83\x3b\x5b\x42\xe4\x3a\xb8\x8a\x33\x32\xd9\xeb\xd1\x01\x27\x44\xe9\x94\xe8\x68\xe6\x73\x4d\x9f\x22\x2f\x88\xd2\x6f\x4a\xc6\x5e\xf9\x12\xa6\x30\xdf\x54\xf6\xbb\x82\xc9\x27\x7c\xcf\xf7\x6d\xa2\x2d\xa1\xc0\x62\x77\xef\x03\x6b\x55\xd8\x7b\x51\x71\x04\xa2\xaa\x9b\x65\xea\xa9\x3e\x00\xd7\x01\x7c\xd2\x83\x45\x5f\x60\xaf\xed\xa4\x2b\xc2\x72\x28\xd3\x5c\xd8\x3b\x96\x42\x24\x8e\x4b\x56\xc2\x2c\x9d\x12\xc2\x14\xec\xb9\xec\x4b\x56\x2c\xe1\xaf\x9c\x4a\x28\x92\xf8\xd9\x32\x2d\x0e\x96\x4e\xae\x80\x55\x93\x63\xcb\x9b\x9e\xf4\x4b\xa4\x24\x37\x6d\xf6\x4d\x29\x7f\xa5\x21\xb5\x22\x18\xd3\x7a\xc4\xc8\xc6\x7e\x0f\x94\x1a\x98\x1e\x58\x58\xba\xb4\xd3\x86\x22\x84\x31\x27\xce\xd7\xdf\xd0\x9e\x9d\xe4\x24\x05\xdf\xd6\x85\xd2\x6e\x67\x77\x6c\x47\x07\xe5\x5c\x0a\xc1\x80\xf0\x7e\x41\x35\xf1\x9a\x38\x2a\xa8\x4f\xa3\x0e\x8c\x1c\x99\xe1\xa3\x65\xb5\x9d\x41\x44\x5a\xd0\x2a\x5d\x38\xa8\x45\x4d\x7c\x91\xb8\x46\x34\x7b\x82\xa2\x59\xde\x06\x6a\x4b\x68\x80\xa3\x7b\x08\xac\xb1\x64\x65\xb2\xb3\xe6\x46\x4a\x57\x60\xdb\x46\x42\x19\x56\xdb\x08\x50\x11\x61\x44\x6e\x23\x41\xd3\xd4\x75\xfc\x46\xfc\x12\x92\x75\xf6\x6d\x89\x56\x4f\x72\x71\x6a\x13\x0c\x3c\x4f\xad\xdd\xec\x56\x2f\xdd\x40\x77\x52\x14\x42\xb8\xa8\x83\xcd\xdf\x94\x5b\xf4\x09\x13\xc4\x1a\x50\x29\x61\xcc\x21\xba\xa4\x53\x77\xa4\x8e\x64\x63\xa8\x70\xa1\xd2\x24\xcd\xb0\x5d\x94\x61\xaf\x27\x0c\xd4\x6c\x51\xe7\x7a\x72\xc5\xb2\xc8\x6d\x84\xec\xea\x8c\xed\x3f\x6a\x4a\xcd\x42\xe7\x4c\x0b\xf8\x5d\xd9\x5e\xc1\xc0\x6b\x3a\x30\x48\x81\xeb\xf5\x6c\xef\xc9\x48\x2b\x0c\x6f\x96\xb1\x2d\x37\x22\xf5\x8e\x4d\xef\x2b\xf1\x9b\x50\xaa\xc0\xbf\x04\x7d\x0b\x6c\x13\xf6\x4d\xc8\xb4\x20\x9f\x6c\x64\xbb\x63\x70\x9b\x5f\x77\xb5\xd7\x7d\x97\x22\xca\x63\x1a\x11\x2d\x64\xb0\xf8\x73\x13\x86\xb7\x84\xe9\x41\xc8\x72\x05\xf3\xd8\x5c\x6c\xe1\xb1\x56\xe0\xad\x92\x24\xb5\xf2\x4f\x2c\x52\x42\xad\x34\x35\x13\x4a\x57\x87\x75\x3b\x96\x4b\x66\xfe\xe4\xa0\x2f\x48\x1c\x4b\x73\x2c\x8d\x1f\x5b\x59\x72\x46\x1e\x39\xbf\xff\xff\xf8\x67\x2b\x11\x5f\xab\x0b\x22\x79\x67\x28\x8a\x44\xce\xf5\x05\x8d\xdd\x19\xca\x95\x26\x3c\x02\xcf\x94\x26\x56\xd6\xd7\x92\x54\x64\xfe\x33\xa6\x39\xca\x76\x85\xb7\x36\xd1\xfb\x21\xa7\x9e\x5f\x01\xd7\xbf\xd3\x4e\x4d\x19\xae\x03\x17\xce\x39\xf2\xa2\xb9\x93\x5b\xec\xfe\x5b\xee\xaa\x6a\xce\xbd\xb0\xb6\x3d\x9f\x67\x39\x65\x7a\x48\x39\x5a\x5a\x84\xea\x66\x40\x87\xc7\x2e\x20\xf1\xb1\x48\x53\xd1\xe5\x53\x5d\xc6\x65\xea\x91\x49\x74\x78\x78\xf8\xa4\xc8\x2b\x39\xa7\xf3\xe6\xdf\x8b\x54\x2d\x3f\xf3\xf6\x93\x2b\xdc\x7b\xe7\xbd\xbd\xd1\xc7\xb9\xd2\x22\xdd\xdc\xe4\xa7\x28\x6a\x39\x6b\x26\x44\x39\x52\x5a\x26\xe5\x10\x17\x9a\x94\xc4\x1d\x49\x46\x33\xe8\x7f\x67\xe4\xe9\xe5\xb3\xe8\x38\x4e\x5e\xbe\xfa\x9c\xbe\xc9\x4e\xdf\x5f\x7f\x9c\xdf\xfc\xf1\xe5\xd3\x24\x5c\x75\x6f\x96\x7e\x07\x16\x82\xec\xd0\x68\xaa\xb4\x5d\x45\x86\x51\xed\x38\x98\x26\x72\x0a\x1d\x3c\xaf\xdb\x5a\x7b\xb4\xb6\x03\xaa\x65\xec\x6b\x48\x63\xbc\xaf\xbd\xb3\x86\x23\xac\x05\x66\x44\xd5\x9c\x93\x95\x9e\x6a\x69\x03\xee\xd2\x32\x07\xaf\xb7\x62\x60\x34\xa5\x3a\xdc\x71\xeb\x3d\xe3\x07\x85\xfd\xe3\xd2\x0b\xa8\x55\xb3\x16\x9c\x90\x9c\x95\x5b\x35\xf0\x6f\x54\x24\x58\x9e\x86\x3b\x25\x9e\xc3\xd2\xd7\x04\x40\x3d\xa7\x68\x6f\xa0\x06\xb6\x3d\xd4\x29\x52\x7f\xd2\xec\x44\x42\x42\xdd\xee\xd4\x6d\xa0\x65\x96\x88\x69\xa6\x6f\x3e\x14\xa5\xdf\x37\xf4\xc4\x4a\x6b\xb5\xa4\xe9\x69\x46\xa2\xdb\x1d\x2b\x30\xcf\x08\x8f\x3b\xbd\x1d\xd4\x73\x27\x84\xb9\x3e\x29\x83\xe6\xb9\xc9\xdb\x0d\xc6\x70\x98\xb5\x2d\xce\x4d\x23\xad\x01\xe2\xea\x38\xfb\x07\xa3\x65\x65\x88\x3b\xdd\xb9\x1f\x81\xf6\x23\xd0\xee\x38\xd0\xda\x16\xfe\xa6\x11\x56\xbd\x18\xac\x8e\x2f\xdf\xcb\xc2\x5d\xee\x4e\xa0\x3b\xdc\xbc\x69\x9c\xd4\xc5\xd3\x7f\x0b\xa3\x5b\x45\xeb\xbf\x09\xbf\xc6\x33\xd1\xae\x00\x5c\x97\xdf\xbf\x15\x1a\xef\xf6\x1d\xe8\x60\xf8\xe4\x62\x72\xdf\xfb\x0a\xb4\xea\x7e\x12\xda\xe1\xed\x9f\x84\x06\xdf\x2e\x94\x37\x4d\xb4\xdf\x55\xc8\x7e\x27\x61\x19\xe0\x5a\x23\x38\x03\x70\xec\x5e\x1e\x1d\x8f\x39\xef\x7e\x6e\xe2\xdf\xfc\xf9\x6f\x15\x68\x7e\xf2\x39\x78\x6d\x49\xc6\x7f\x99\x29\x15\x44\xd7\x54\xcf\x50\xc6\x48\x04\x33\xc1\x8a\x62\xd0\x22\xdf\x8f\x44\x5a\xf7\x9b\xf1\x9b\x5c\x69\x14\x09\xae\x09\xe5\x88\x68\xc4\x80\x28\x8d\x04\x87\x30\xbb\xd9\x3b\x18\x8f\xbf\x8e\xc7\xea\xfe\xd9\xf9\x62\xf2\xa0\xf8\x18\x8f\x17\xab\xdf\x6b\x36\x36\x45\xe4\x1a\x71\xb8\x66\x94\x83\x0a\x9b\xf2\x96\xb3\x1b\x44\x18\x13\xd7\x0d\x71\x61\x90\x9e\x01\x02\x1e\x07\x4d\x38\x3f\x3b\x1f\x8f\x79\xa1\x3d\xff\x75\x3f\xf8\x58\xb4\x57\xfc\x59\xec\xfd\x1d\x00\x00\xff\xff\x48\x24\xa3\x61\xd9\x24\x00\x00")

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
	"schema.json": &bintree{schemaJson, map[string]*bintree{}},
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
