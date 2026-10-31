// Commande ogsbom-server. Le câblage complet arrive avec les lots qui la concernent ;
// en attendant, elle n'affiche que sa version.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version est injectée à la construction : -ldflags "-X 'main.version=…'".
var version = "develop"

func main() {
	showVersion := flag.Bool("version", false, "affiche la version et quitte")
	flag.Parse()
	if *showVersion {
		fmt.Printf("ogsbom-server %s\n", version)
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "ogsbom-server: pas encore implémenté")
	os.Exit(1)
}
