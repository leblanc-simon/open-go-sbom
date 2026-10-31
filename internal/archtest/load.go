package archtest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
)

// listedPackage reprend les champs utiles de la sortie de go list -json.
type listedPackage struct {
	ImportPath   string
	Module       *struct{ Path string }
	Imports      []string
	TestImports  []string
	XTestImports []string
	Error        *struct{ Err string }
}

// Load lit les paquets du module situé dans dir par go list. Il renvoie le chemin du
// module et ses paquets, imports de test compris.
func Load(ctx context.Context, dir string) (string, []Package, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-json", "./...")
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", nil, fmt.Errorf("go list dans %s : %w : %s", dir, err, stderr.String())
	}
	return decode(&stdout)
}

func decode(r io.Reader) (string, []Package, error) {
	var module string
	var pkgs []Package
	dec := json.NewDecoder(r)
	for {
		var lp listedPackage
		err := dec.Decode(&lp)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("décodage de go list : %w", err)
		}
		if lp.Error != nil {
			return "", nil, fmt.Errorf("paquet %s : %s", lp.ImportPath, lp.Error.Err)
		}
		if lp.Module == nil {
			return "", nil, fmt.Errorf("paquet %s hors module", lp.ImportPath)
		}
		module = lp.Module.Path
		rel := strings.TrimPrefix(strings.TrimPrefix(lp.ImportPath, module), "/")
		imports := slices.Concat(lp.Imports, lp.TestImports, lp.XTestImports)
		slices.Sort(imports)
		pkgs = append(pkgs, Package{Path: rel, Imports: slices.Compact(imports)})
	}
	return module, pkgs, nil
}
