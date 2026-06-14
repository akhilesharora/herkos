//go:build cgo

package treesitter

import (
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// tsDeclTypes are the TypeScript/JavaScript node types treated as top-level declarations.
var tsDeclTypes = map[string]bool{
	"function_declaration": true,
	"class_declaration":    true,
}

// pyDeclTypes are the Python node types treated as top-level declarations.
var pyDeclTypes = map[string]bool{
	"function_definition": true,
	"class_definition":    true,
}

// ParseTypeScript parses TypeScript/JavaScript source into a Graph (declarations + edges).
func ParseTypeScript(file string, src []byte) (*Graph, error) {
	return build(file, src, typescript.GetLanguage(), tsDeclTypes)
}

// ParsePython parses Python source into a Graph (declarations + edges).
func ParsePython(file string, src []byte) (*Graph, error) {
	return build(file, src, python.GetLanguage(), pyDeclTypes)
}
