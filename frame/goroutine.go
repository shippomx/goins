package frame

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"os"

	"github.com/Knetic/govaluate"
	sgr "github.com/foize/go.sgr"
)

type MetaType int

var (
	MetaState    MetaType = 0
	MetaDuration MetaType = 1

	durationPattern = regexp.MustCompile(`^\d+ minutes$`)

	functions = map[string]govaluate.ExpressionFunction{
		"contains": func(args ...interface{}) (interface{}, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("contains() accepts exactly two arguments")
			}
			idx := strings.Index(args[0].(string), args[1].(string))
			return bool(idx > -1), nil
		},
		"lower": func(args ...interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("lower() accepts exactly one arguments")
			}
			lowered := strings.ToLower(args[0].(string))
			return string(lowered), nil
		},
		"upper": func(args ...interface{}) (interface{}, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("upper() accepts exactly one arguments")
			}
			uppered := strings.ToUpper(args[0].(string))
			return string(uppered), nil
		},
	}
)

// Goroutine contains a goroutine info.
type Goroutine struct {
	Id       int
	Header   string
	Trace    string
	Lines    int
	Duration int // In minutes.
	Metas    map[MetaType]string

	LineMd5      []string
	FullMd5      string
	FullHasher   hash.Hash
	Duplicates   []ShortSlim
	IsLockHolder bool
	LockHolders  []string

	Frozen bool
	Buf    *bytes.Buffer
}

type ShortSlim struct {
	Gid      int
	Duration int
}

// AddLine appends a line to the goroutine info.
func (g *Goroutine) AddLine(l string) {
	if !g.Frozen {
		g.Lines++
		g.Buf.WriteString(l)
		g.Buf.WriteString("\n")

		if strings.HasPrefix(l, "\t") {
			// caller location
			parts := strings.Split(l, " ")
			fl := strings.TrimSpace(parts[0])

			h := md5.New()
			io.WriteString(h, fl)
			g.LineMd5 = append(g.LineMd5, string(h.Sum(nil)))

			io.WriteString(g.FullHasher, fl)
		} else {
			// caller
			if !g.IsLockHolder && strings.Contains(l, ".Lock") {
				g.IsLockHolder = true
			}
			if g.IsLockHolder {
				// reg := regexp.MustCompile(`([\D\w.\-\/\(\*\)]+)\(([0x\w, ]+)\)`) // full function name
				// caller := reg.FindStringSubmatch(l)
				// if len(caller) == 3 {
				// 	// caller[1]: caller
				// 	// caller[2]: params
				// }
				reg := regexp.MustCompile(`(\*\w+)`) // only short Caller
				caller := reg.FindStringSubmatch(l)
				if len(caller) > 0 {
					g.LockHolders = append(g.LockHolders, caller[0])
				}
			}
		}
	}
}

// Freeze freezes the goroutine info.
func (g *Goroutine) Freeze() {
	if !g.Frozen {
		g.Frozen = true
		g.Trace = g.Buf.String()
		g.Buf = nil

		g.FullMd5 = string(g.FullHasher.Sum(nil))
	}
}

// Print outputs the goroutine details to w.
func (g Goroutine) Print(w io.Writer) error {
	if _, err := fmt.Fprint(w, g.Header); err != nil {
		return err
	}
	if len(g.Duplicates) > 0 {
		if _, err := fmt.Fprintf(w, " %d times: [[", len(g.Duplicates)); err != nil {
			return err
		}
		for i, dep := range g.Duplicates {
			if i > 0 {
				if _, err := fmt.Fprint(w, ", "); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, dep); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, "]"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, g.Trace); err != nil {
		return err
	}
	return nil
}

// PrintWithColor outputs the goroutine details to stdout with color.
func (g Goroutine) PrintWithColor() {
	sgr.Printf("[fg-blue]%s[reset]", g.Header)
	if len(g.Duplicates) > 0 {
		sgr.Printf(" [fg-red]%d[reset] times: ({Gid, Duration})[[", len(g.Duplicates))
		for i, dep := range g.Duplicates {
			if i > 0 {
				sgr.Printf(", ")
			}
			sgr.Printf("[fg-green]%v[reset]", dep)
		}
		sgr.Print("]")
	}
	sgr.Println()
	fmt.Println(g.Trace)
}

// NewGoroutine creates and returns a new Goroutine.
func NewGoroutine(metaline string) (*Goroutine, error) {
	idx := strings.Index(metaline, "[")
	parts := strings.Split(metaline[idx+1:len(metaline)-2], ",")
	metas := map[MetaType]string{
		MetaState: strings.TrimSpace(parts[0]),
	}

	duration := 0
	if len(parts) > 1 {
		value := strings.TrimSpace(parts[1])
		metas[MetaDuration] = value
		if durationPattern.MatchString(value) {
			if d, err := strconv.Atoi(value[:len(value)-8]); err == nil {
				duration = d
			}
		}
	}

	idstr := strings.TrimSpace(metaline[9:idx])
	id, err := strconv.Atoi(idstr)
	if err != nil {
		return nil, err
	}

	return &Goroutine{
		Id:         id,
		Lines:      1,
		Header:     metaline,
		Buf:        &bytes.Buffer{},
		Duration:   duration,
		Metas:      metas,
		FullHasher: md5.New(),
		Duplicates: []ShortSlim{},
	}, nil
}

// GoroutineDump defines a goroutine dump.
type GoroutineDump struct {
	goroutines []*Goroutine
}

// Add appends a goroutine info to the list.
func (gd *GoroutineDump) Add(g *Goroutine) {
	gd.goroutines = append(gd.goroutines, g)
}

// Copy duplicates and returns the GoroutineDump.
func (gd GoroutineDump) Copy(cond string) *GoroutineDump {
	dump := GoroutineDump{
		goroutines: []*Goroutine{},
	}
	if cond == "" {
		// Copy all.
		for _, d := range gd.goroutines {
			dump.goroutines = append(dump.goroutines, d)
		}
	} else {
		goroutines, err := gd.withCondition(cond, func(i int, g *Goroutine, passed bool) *Goroutine {
			if passed {
				return g
			}
			return nil
		})
		if err != nil {
			fmt.Println(err)
			return nil
		}
		dump.goroutines = goroutines
	}
	return &dump
}

// Dedup finds goroutines with duplicated stack traces and keeps only one copy
// of them.

func (gd *GoroutineDump) Dedup() []*Goroutine {
	m := map[string][]ShortSlim{}
	for _, g := range gd.goroutines {
		if _, ok := m[g.FullMd5]; ok {
			m[g.FullMd5] = append(m[g.FullMd5], ShortSlim{Gid: g.Id, Duration: g.Duration})
		} else {
			m[g.FullMd5] = append([]ShortSlim{}, ShortSlim{Gid: g.Id, Duration: g.Duration})
		}
	}

	kept := make([]*Goroutine, 0, len(gd.goroutines))

outter:
	for digest, ids := range m {
		for _, g := range gd.goroutines {
			if g.FullMd5 == digest {
				g.Duplicates = ids
				kept = append(kept, g)
				continue outter
			}
		}
	}

	if len(gd.goroutines) != len(kept) {
		fmt.Printf("Dedupped %d, kept %d\n", len(gd.goroutines), len(kept))
		gd.goroutines = kept
	}
	return kept
}

// Delete deletes by the condition.
func (gd *GoroutineDump) Delete(cond string) error {
	goroutines, err := gd.withCondition(cond, func(i int, g *Goroutine, passed bool) *Goroutine {
		if !passed {
			return g
		}
		return nil
	})
	if err != nil {
		return err
	}
	gd.goroutines = goroutines
	return nil
}

// Diff shows the difference between two dumps.
func (gd *GoroutineDump) Diff(another *GoroutineDump) (*GoroutineDump, *GoroutineDump, *GoroutineDump) {
	lonly := map[int]*Goroutine{}
	ronly := map[int]*Goroutine{}
	common := map[int]*Goroutine{}

	for _, v := range gd.goroutines {
		lonly[v.Id] = v
	}
	for _, v := range another.goroutines {
		if _, ok := lonly[v.Id]; ok {
			delete(lonly, v.Id)
			common[v.Id] = v
		} else {
			ronly[v.Id] = v
		}
	}
	return NewGoroutineDumpFromMap(lonly), NewGoroutineDumpFromMap(common), NewGoroutineDumpFromMap(ronly)
}

// Keep keeps by the condition.
func (gd *GoroutineDump) Keep(cond string) error {
	goroutines, err := gd.withCondition(cond, func(i int, g *Goroutine, passed bool) *Goroutine {
		if passed {
			return g
		}
		return nil
	})
	if err != nil {
		return err
	}
	gd.goroutines = goroutines
	return nil
}

// Save saves the goroutine dump to the given file.
func (gd GoroutineDump) Save(fn string) error {
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, g := range gd.goroutines {
		if err := g.Print(f); err != nil {
			return err
		}
	}
	return nil
}

// Search displays the goroutines with the offset and limit.
func (gd GoroutineDump) Search(cond string, offset, limit int) {
	sgr.Printf("[fg-green]Search with offset %d and limit %d.[reset]\n\n", offset, limit)

	count := 0
	_, err := gd.withCondition(cond, func(i int, g *Goroutine, passed bool) *Goroutine {
		if passed {
			if count >= offset && count < offset+limit {
				g.PrintWithColor()
			}
			count++
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
}

// Show displays the goroutines with the offset and limit.
func (gd GoroutineDump) Show(offset, limit int) {
	for i := offset; i < offset+limit && i < len(gd.goroutines); i++ {
		gd.goroutines[offset+i].PrintWithColor()
	}
}

// Sort sorts the goroutine entries.
func (gd *GoroutineDump) Sort() {
	fmt.Printf("# of goroutines: %d\n", len(gd.goroutines))
}

// Summary prints the summary of the goroutine dump.
func (gd GoroutineDump) Summary() {
	fmt.Printf("# of goroutines: %d\n", len(gd.goroutines))
	stats := map[string]int{}
	if len(gd.goroutines) > 0 {
		for _, g := range gd.goroutines {
			stats[g.Metas[MetaState]]++
		}
		fmt.Println()
	}
	if len(stats) > 0 {
		states := make([]string, 0, 10)
		for k := range stats {
			states = append(states, k)
		}
		sort.Sort(sort.StringSlice(states))

		for _, k := range states {
			fmt.Printf("%15s: %d\n", k, stats[k])
		}
		fmt.Println()
	}
}

// NewGoroutineDump creates and returns a new GoroutineDump.
func NewGoroutineDump() *GoroutineDump {
	return &GoroutineDump{
		goroutines: []*Goroutine{},
	}
}

// NewGoroutineDumpFromMap creates and returns a new GoroutineDump from a map.
func NewGoroutineDumpFromMap(gs map[int]*Goroutine) *GoroutineDump {
	gd := &GoroutineDump{
		goroutines: []*Goroutine{},
	}
	for _, v := range gs {
		gd.goroutines = append(gd.goroutines, v)
	}
	return gd
}

func (gd *GoroutineDump) withCondition(cond string, callback func(int, *Goroutine, bool) *Goroutine) ([]*Goroutine, error) {
	cond = strings.Trim(cond, "\"")
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(cond, functions)
	if err != nil {
		return nil, err
	}

	goroutines := make([]*Goroutine, 0, len(gd.goroutines))
	for i, g := range gd.goroutines {
		params := map[string]interface{}{
			"id":       g.Id,
			"dups":     len(g.Duplicates),
			"duration": g.Duration,
			"lines":    g.Lines,
			"state":    g.Metas[MetaState],
			"trace":    g.Trace,
		}
		res, err := expression.Evaluate(params)
		if err != nil {
			return nil, err
		}
		if val, ok := res.(bool); ok {
			if gor := callback(i, g, val); gor != nil {
				goroutines = append(goroutines, gor)
			}
		} else {
			return nil, errors.New("argument expression should return a boolean")
		}
	}
	fmt.Printf("Deleted %d goroutines, kept %d.\n", len(gd.goroutines)-len(goroutines), len(goroutines))
	return goroutines, nil
}

func HasDeadLock(f1, f2 *Goroutine) bool {
	if len(f1.LockHolders) < 1 || len(f2.LockHolders) < 1 {
		return false
	}
	for idxi, hi1 := range f1.LockHolders {
		for idxj, hj1 := range f2.LockHolders {
			if hi1 == hj1 { // find the first equal pair
				for j := idxj + 1; j < len(f2.LockHolders); j++ {
					thj := f2.LockHolders[j]
					for i := idxi - 1; i > 0; i-- {
						thi := f1.LockHolders[i]
						if thi == thj { // find the second equal pair
							return true
						}
					}
				}
			}
		}
	}
	return false
}
