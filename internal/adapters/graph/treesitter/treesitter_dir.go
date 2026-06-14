//go:build cgo

package treesitter

import (
	"io/fs"
	"os"
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/akhilesharora/herkos/internal/core/spanselect"
)

// langForExt returns the tree-sitter language and declaration types for a file extension,
// and whether the extension is a supported source file. JS/TS/JSX/TSX all use the
// TypeScript grammar (a superset that parses plain JS), which is coarse but sufficient.
func langForExt(ext string) (*sitter.Language, map[string]bool, bool) {
	switch ext {
	case ".go":
		return golang.GetLanguage(), goDeclTypes, true
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		return typescript.GetLanguage(), tsDeclTypes, true
	case ".py":
		return python.GetLanguage(), pyDeclTypes, true
	}
	return nil, nil, false
}

// skipDir reports whether a directory should not be walked: VCS and dependency/build dirs,
// plus any hidden directory.
func skipDir(name string) bool {
	switch name {
	case "node_modules", "vendor", ".git", "dist", "build":
		return true
	}
	return len(name) > 1 && name[0] == '.'
}

// ParseDirNodes walks root and parses every supported source file into one merged set of
// graph nodes with cross-file edges: a reference to a symbol defined in another file becomes
// an edge. File spans are stored relative to root so the index is portable. Files that fail
// to read or parse are skipped rather than aborting the whole index.
func ParseDirNodes(root string) ([]spanselect.Node, error) {
	var all []parsedDecl
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		lang, declTypes, ok := langForExt(filepath.Ext(d.Name()))
		if !ok {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil // unreadable file: skip, do not fail the index
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		decls, err := parseDecls(filepath.ToSlash(rel), src, lang, declTypes)
		if err != nil {
			return nil // unparseable file: skip
		}
		all = append(all, decls...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resolveNodes(all), nil
}

// ParseDir walks root and returns a queryable Graph over the whole tree.
func ParseDir(root string) (*Graph, error) {
	nodes, err := ParseDirNodes(root)
	if err != nil {
		return nil, err
	}
	return &Graph{g: spanselect.NewGraph(nodes)}, nil
}
