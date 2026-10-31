package sbom

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Limits sont les bornes préalables d'un SBOM, vérifiées en flux avant tout décodage
// complet (§ 11 de l'architecture).
type Limits struct {
	// MaxBytes borne la taille du JSON (décompressé).
	MaxBytes int64
	// MaxDepth borne l'imbrication des objets et tableaux (l'objet racine compte pour 1).
	MaxDepth int
	// MaxComponents borne le nombre d'éléments des tableaux « components » (CycloneDX, à
	// toute profondeur), « packages » (SPDX) et « artifacts » (Syft).
	MaxComponents int
}

// Header est ce que Precheck a lu du document : format, version de spécification et
// mesures.
type Header struct {
	Format      Format
	SpecVersion string
	Bytes       int64
	Depth       int
	Components  int
}

// Versions acceptées par format.
var (
	cycloneDXVersions = []string{"1.5", "1.6", "1.7"}
	spdxVersions      = map[string]string{"SPDX-2.3": "2.3"}
)

// errTooLarge interrompt la lecture au-delà de MaxBytes.
var errTooLarge = errors.New("sbom: document trop volumineux")

// Precheck lit le document en flux, sans le charger : il vérifie que c'est un objet JSON
// bien formé et que taille, profondeur et nombre de composants restent dans les bornes,
// puis reconnaît le format. La lecture s'arrête à la première borne franchie. Les clés
// sont comparées sans tenir compte de la casse, comme le fait encoding/json au décodage :
// « COMPONENTS » ne contourne pas le compte.
func Precheck(r io.Reader, l Limits) (Header, error) {
	if l.MaxBytes <= 0 || l.MaxDepth <= 0 || l.MaxComponents < 0 {
		return Header{}, errors.New("sbom: bornes préalables invalides")
	}
	lr := &limitedReader{r: r, left: l.MaxBytes}
	s := &scanner{r: bufio.NewReaderSize(lr, 64<<10), limits: l}
	err := s.document()
	h := Header{Bytes: lr.read, Depth: s.maxDepth, Components: s.components}
	if err != nil {
		return h, s.classify(err)
	}
	h.Format, h.SpecVersion, err = s.top.detect()
	return h, err
}

type limitedReader struct {
	r    io.Reader
	left int64
	read int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		// Un octet de plus que la borne prouve le dépassement.
		var one [1]byte
		n, err := l.r.Read(one[:])
		if n > 0 {
			return 0, errTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	l.read += int64(n)
	return n, err
}

// topLevel retient les clés de premier niveau qui désignent le format.
type topLevel struct {
	bomFormat, specVersion, spdxVersion, syftSchemaVersion string
	hasArtifacts, hasSchema                                bool
}

func (t topLevel) detect() (Format, string, error) {
	switch {
	case t.bomFormat != "":
		if t.bomFormat != "CycloneDX" {
			return "", "", Reject(KeyUnsupportedFormat, "bomFormat", nil)
		}
		for _, v := range cycloneDXVersions {
			if t.specVersion == v {
				return FormatCycloneDX, v, nil
			}
		}
		return "", "", Reject(KeyUnsupportedFormat, "cyclonedx "+printable(t.specVersion), nil)
	case t.spdxVersion != "":
		if v, ok := spdxVersions[t.spdxVersion]; ok {
			return FormatSPDX, v, nil
		}
		return "", "", Reject(KeyUnsupportedFormat, printable(t.spdxVersion), nil)
	case t.hasArtifacts && t.hasSchema && t.syftSchemaVersion != "":
		return FormatSyft, t.syftSchemaVersion, nil
	}
	return "", "", Reject(KeyUnsupportedFormat, "", nil)
}

// printable borne et nettoie une valeur du document reprise dans un détail d'erreur.
func printable(s string) string {
	if len(s) > 16 {
		s = s[:16]
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

type scanner struct {
	r          *bufio.Reader
	limits     Limits
	maxDepth   int
	components int
	top        topLevel
}

var (
	errSyntax  = errors.New("sbom: JSON mal formé")
	errDepth   = errors.New("sbom: JSON trop profond")
	errTooMany = errors.New("sbom: trop de composants")
	errNotJSON = errors.New("sbom: pas un objet JSON")
)

func (s *scanner) classify(err error) error {
	switch {
	case errors.Is(err, errTooLarge):
		return Reject(KeyTooLarge, "", err)
	case errors.Is(err, errDepth):
		return Reject(KeyTooDeep, "", err)
	case errors.Is(err, errTooMany):
		return Reject(KeyTooManyComponents, "", err)
	case errors.Is(err, errNotJSON):
		return Reject(KeyUnsupportedFormat, "", err)
	}
	// Fin prématurée, syntaxe, flux compressé corrompu : document illisible.
	return Reject(KeyMalformed, "", err)
}

func (s *scanner) next() (byte, error) {
	c, err := s.r.ReadByte()
	if errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("%w : fin prématurée", errSyntax)
	}
	return c, err
}

// skipSpace renvoie le premier octet non blanc ; eof vrai en fin de flux.
func (s *scanner) skipSpace() (c byte, eof bool, err error) {
	for {
		c, err = s.r.ReadByte()
		if errors.Is(err, io.EOF) {
			return 0, true, nil
		}
		if err != nil {
			return 0, false, err
		}
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return c, false, nil
	}
}

func (s *scanner) document() error {
	c, eof, err := s.skipSpace()
	switch {
	case err != nil:
		return err
	case eof:
		return fmt.Errorf("%w : document vide", errSyntax)
	case c == '<':
		return fmt.Errorf("%w : XML", errNotJSON)
	case c != '{':
		return fmt.Errorf("%w : la racine n'est pas un objet", errNotJSON)
	}
	if err := s.object(1, ctxRoot); err != nil {
		return err
	}
	c, eof, err = s.skipSpace()
	if err != nil {
		return err
	}
	if !eof {
		return fmt.Errorf("%w : contenu après la racine (%q)", errSyntax, c)
	}
	return nil
}

// ctx dit ce que le scanner doit retenir d'une valeur selon sa place.
type ctx int

const (
	ctxNone       ctx = iota
	ctxRoot           // objet racine : clés de format
	ctxSyftSchema     // objet « schema » de premier niveau : sa version
	ctxCounted        // tableau dont chaque élément compte pour un composant
)

func (s *scanner) enter(depth int) error {
	if depth > s.limits.MaxDepth {
		return errDepth
	}
	if depth > s.maxDepth {
		s.maxDepth = depth
	}
	return nil
}

// object lit un objet dont « { » est déjà consommé.
func (s *scanner) object(depth int, at ctx) error {
	if err := s.enter(depth); err != nil {
		return err
	}
	c, err := s.nonSpace()
	if err != nil {
		return err
	}
	if c == '}' {
		return nil
	}
	for {
		if c != '"' {
			return fmt.Errorf("%w : clé attendue", errSyntax)
		}
		key, err := s.str(32)
		if err != nil {
			return err
		}
		if c, err = s.nonSpace(); err != nil {
			return err
		}
		if c != ':' {
			return fmt.Errorf("%w : « : » attendu", errSyntax)
		}
		if err := s.member(depth, at, key); err != nil {
			return err
		}
		if c, err = s.nonSpace(); err != nil {
			return err
		}
		switch c {
		case ',':
			if c, err = s.nonSpace(); err != nil {
				return err
			}
		case '}':
			return nil
		default:
			return fmt.Errorf("%w : « , » ou « } » attendu", errSyntax)
		}
	}
}

// member lit la valeur de la clé key d'un objet de profondeur depth.
func (s *scanner) member(depth int, at ctx, key string) error {
	child := ctxNone
	var capture *string
	switch {
	case isKey(key, "components", "packages", "artifacts"):
		child = ctxCounted
	}
	switch at {
	case ctxRoot:
		switch {
		case isKey(key, "bomFormat"):
			capture = &s.top.bomFormat
		case isKey(key, "specVersion"):
			capture = &s.top.specVersion
		case isKey(key, "spdxVersion"):
			capture = &s.top.spdxVersion
		case isKey(key, "artifacts"):
			s.top.hasArtifacts = true
		case isKey(key, "schema"):
			s.top.hasSchema = true
			child = ctxSyftSchema
		}
	case ctxSyftSchema:
		if isKey(key, "version") {
			capture = &s.top.syftSchemaVersion
		}
	}
	c, err := s.nonSpace()
	if err != nil {
		return err
	}
	if capture != nil && c == '"' {
		v, err := s.str(64)
		*capture = v
		return err
	}
	return s.value(c, depth, child)
}

func isKey(key string, names ...string) bool {
	for _, n := range names {
		if strings.EqualFold(key, n) {
			return true
		}
	}
	return false
}

// value lit une valeur dont le premier octet c est déjà consommé ; depth est la profondeur
// du conteneur parent.
func (s *scanner) value(c byte, depth int, at ctx) error {
	switch {
	case c == '{':
		if at == ctxSyftSchema && depth == 1 {
			return s.object(depth+1, ctxSyftSchema)
		}
		return s.object(depth+1, ctxNone)
	case c == '[':
		return s.array(depth+1, at == ctxCounted)
	case c == '"':
		_, err := s.str(0)
		return err
	case c == 't':
		return s.literal("rue")
	case c == 'f':
		return s.literal("alse")
	case c == 'n':
		return s.literal("ull")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number(c)
	}
	return fmt.Errorf("%w : valeur attendue", errSyntax)
}

// array lit un tableau dont « [ » est déjà consommé ; counted : chaque élément est un
// composant.
func (s *scanner) array(depth int, counted bool) error {
	if err := s.enter(depth); err != nil {
		return err
	}
	c, err := s.nonSpace()
	if err != nil {
		return err
	}
	if c == ']' {
		return nil
	}
	for {
		if counted {
			s.components++
			if s.components > s.limits.MaxComponents {
				return errTooMany
			}
		}
		if err := s.value(c, depth, ctxNone); err != nil {
			return err
		}
		if c, err = s.nonSpace(); err != nil {
			return err
		}
		switch c {
		case ',':
			if c, err = s.nonSpace(); err != nil {
				return err
			}
		case ']':
			return nil
		default:
			return fmt.Errorf("%w : « , » ou « ] » attendu", errSyntax)
		}
	}
}

func (s *scanner) nonSpace() (byte, error) {
	c, eof, err := s.skipSpace()
	if err != nil {
		return 0, err
	}
	if eof {
		return 0, fmt.Errorf("%w : fin prématurée", errSyntax)
	}
	return c, nil
}

func (s *scanner) literal(rest string) error {
	for i := 0; i < len(rest); i++ {
		c, err := s.next()
		if err != nil {
			return err
		}
		if c != rest[i] {
			return fmt.Errorf("%w : littéral", errSyntax)
		}
	}
	return s.endOfScalar()
}

// endOfScalar vérifie qu'un littéral ou un nombre est suivi d'un délimiteur.
func (s *scanner) endOfScalar() error {
	b, err := s.r.Peek(1)
	if len(b) == 0 {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	switch b[0] {
	case ' ', '\t', '\n', '\r', ',', '}', ']':
		return nil
	}
	return fmt.Errorf("%w : délimiteur attendu", errSyntax)
}

// number lit un nombre JSON (grammaire de la RFC 8259) dont le premier octet est lu.
func (s *scanner) number(first byte) error {
	c := first
	var err error
	if c == '-' {
		if c, err = s.next(); err != nil {
			return err
		}
	}
	switch {
	case c == '0':
	case c >= '1' && c <= '9':
		if err := s.digits(false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w : nombre", errSyntax)
	}
	if s.peekIs('.') {
		_, _ = s.r.ReadByte()
		if err := s.digits(true); err != nil {
			return err
		}
	}
	if s.peekIs('e') || s.peekIs('E') {
		_, _ = s.r.ReadByte()
		if s.peekIs('+') || s.peekIs('-') {
			_, _ = s.r.ReadByte()
		}
		if err := s.digits(true); err != nil {
			return err
		}
	}
	return s.endOfScalar()
}

func (s *scanner) peekIs(c byte) bool {
	b, _ := s.r.Peek(1)
	return len(b) == 1 && b[0] == c
}

// digits lit une suite de chiffres ; required : au moins un.
func (s *scanner) digits(required bool) error {
	n := 0
	for {
		b, err := s.r.Peek(1)
		if len(b) == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
		if b[0] < '0' || b[0] > '9' {
			break
		}
		_, _ = s.r.ReadByte()
		n++
	}
	if required && n == 0 {
		return fmt.Errorf("%w : chiffre attendu", errSyntax)
	}
	return nil
}

// str lit une chaîne dont le guillemet ouvrant est consommé et en renvoie la valeur
// décodée si elle tient en keep octets (vide sinon, ou si keep vaut 0).
func (s *scanner) str(keep int) (string, error) {
	var b []byte
	overflow := keep == 0
	add := func(r rune) {
		if overflow {
			return
		}
		b = utf8.AppendRune(b, r)
		if len(b) > keep {
			overflow, b = true, nil
		}
	}
	for {
		c, err := s.next()
		if err != nil {
			return "", err
		}
		switch {
		case c == '"':
			return string(b), nil
		case c < 0x20:
			return "", fmt.Errorf("%w : caractère de contrôle dans une chaîne", errSyntax)
		case c == '\\':
			r, err := s.escape()
			if err != nil {
				return "", err
			}
			add(r)
		case c < utf8.RuneSelf:
			add(rune(c))
		default:
			// Octet d'une séquence UTF-8 : recopié tel quel (seules les clés ASCII
			// comptent).
			if !overflow {
				b = append(b, c)
				if len(b) > keep {
					overflow, b = true, nil
				}
			}
		}
	}
}

func (s *scanner) escape() (rune, error) {
	c, err := s.next()
	if err != nil {
		return 0, err
	}
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		r, err := s.hex4()
		if err != nil {
			return 0, err
		}
		if utf16.IsSurrogate(r) {
			// Une paire de substitution décode un caractère hors du plan de base, jamais
			// une lettre ASCII : sa valeur exacte n'importe pas ici.
			return utf8.RuneError, nil
		}
		return r, nil
	}
	return 0, fmt.Errorf("%w : échappement", errSyntax)
}

func (s *scanner) hex4() (rune, error) {
	var r rune
	for range 4 {
		c, err := s.next()
		if err != nil {
			return 0, err
		}
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, fmt.Errorf("%w : échappement \\u", errSyntax)
		}
		r = r<<4 | rune(v)
	}
	return r, nil
}
