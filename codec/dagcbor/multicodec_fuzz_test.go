package dagcbor

import (
	"flag"
	"os"
	"testing"

	fleece "github.com/leastauthority/fleece/fuzzing"
	"github.com/stretchr/testify/require"
)

var (
	crashLimit  int
	fleeceDir   string
	skipPattern string
	safe        bool

	env *fleece.Env
)

func init() {
	flag.IntVar(&crashLimit, "crash-limit", 1000, "number of crashing inputs to test before stopping")
	flag.StringVar(&fleeceDir, "fleece-dir", "fleece", "path to fleece dir relative to repo/module root")
	flag.StringVar(&skipPattern, "skip", "", "if provided, crashers with recorded outputs which match the pattern will be skipped")
	flag.BoolVar(&safe, "safe", true, "\"if true, skips crashers with recorded outputs that timed-out or ran out of memory\"")
}

func TestMain(m *testing.M) {
	flag.Parse()
	env = fleece.NewEnv(fleeceDir)

	os.Exit(m.Run())
}

func TestFuzzMulticodecDecodeEncode(t *testing.T) {
	filters := []fleece.IterFilter{fleece.SkipFilter(skipPattern)}
	if safe {
		filters = append(filters,
			fleece.SkipTimedOut,
			fleece.SkipOutOfMemory)
	}

	_, panics, _ := fleece.
		MustNewCrasherIterator(env, FuzzMulticodecDecodeEncode, filters...).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}
