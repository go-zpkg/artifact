package artifact

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// failNamespace makes every request into one namespace of the fake registry
// answer 500: a source that cannot be read, which is not a source that lacks
// the package.
func failNamespace(fr *fakeRegistry, ns string) {
	fr.hook = func(r *http.Request) (int, bool) {
		if strings.Contains(r.URL.Path, "/"+ns+"/") {
			return http.StatusInternalServerError, true
		}
		return 0, false
	}
}

func TestASourceThatCannotBeReadStopsTheWalk(t *testing.T) {
	_, zpkg, kp, fr := twoSourcesFR(t)
	pushSignedArtifact(t, zpkg, "published.test", kp, makeGzTarball("p"), true)
	failNamespace(fr, "run/packages")

	// The second source has it, but the first could not answer: carrying on
	// would resolve a package from a source that may be shadowed by the one we
	// could not read.
	_, _, err := versionsForSourced("published.test", "linux", "x86-64")
	if err == nil || !strings.Contains(err.Error(), "dist source") {
		t.Errorf("versionsForSourced past an unreadable source: %v", err)
	}
	if _, _, err := publishedTagFor("published.test", ParseVer("1.0.0"), "linux", "x86-64"); err == nil {
		t.Error("publishedTagFor carried on past an unreadable source")
	}
}

func TestASingleUnreadableSourceIsAnError(t *testing.T) {
	_, zpkg, kp, fr := twoSourcesFR(t)
	pushSignedArtifact(t, zpkg, "published.test", kp, makeGzTarball("p"), true)
	DistBase, DistExtra = fr.base("go-zpkg/packages"), nil
	resetOCICache()
	failNamespace(fr, "go-zpkg/packages")
	if _, ok, err := publishedTagFor("published.test", ParseVer("1.0.0"), "linux", "x86-64"); err == nil || ok {
		t.Errorf("publishedTagFor on an unreadable source: ok=%v err=%v", ok, err)
	}
}

// With one source the errors are the plain ones, not wrapped in a list's
// framing; with two they name every source.
func TestErrorsNameTheSourcesOnlyWhenThereIsAList(t *testing.T) {
	_, _, _, fr := twoSourcesFR(t)
	only := fr.base("run/packages")
	DistBase, DistExtra = only, nil
	resetOCICache()

	_, _, err := DownloadArtifact("nowhere.test", "1.0.0", "linux", "x86-64")
	if err == nil || strings.Contains(err.Error(), only) {
		t.Errorf("DownloadArtifact, one source: %v", err)
	}
	_, _, _, err = fetchArtifact(Resolved{Project: "nowhere.test", Version: ParseVer("1.0.0")}, "linux", "x86-64")
	if err == nil || strings.Contains(err.Error(), "dist source") {
		t.Errorf("fetchArtifact, one source: %v", err)
	}

	other := fr.base("go-zpkg/packages")
	DistBase, DistExtra = only, []string{other}
	resetOCICache()
	_, _, err = DownloadArtifact("nowhere.test", "1.0.0", "linux", "x86-64")
	if err == nil || !strings.Contains(err.Error(), only) || !strings.Contains(err.Error(), other) {
		t.Errorf("DownloadArtifact, two sources: %v", err)
	}
	_, _, _, err = fetchArtifact(Resolved{Project: "nowhere.test", Version: ParseVer("1.0.0")}, "linux", "x86-64")
	if err == nil || !strings.Contains(err.Error(), "dist source "+only) || !strings.Contains(err.Error(), "dist source "+other) {
		t.Errorf("fetchArtifact, two sources: %v", err)
	}
}

func TestASuccessfulFetchReturnsTheStream(t *testing.T) {
	stage, _, kp := twoSources(t)
	pushSignedArtifact(t, stage, "inrun.test", kp, makeGzTarball("x"), true)
	f, ext, digest, err := fetchArtifact(Resolved{Project: "inrun.test", Version: ParseVer("1.0.0")}, "linux", "x86-64")
	if err != nil || f == nil || ext != ExtTarGz || digest == "" {
		t.Fatalf("fetchArtifact = %v %q %q %v", f, ext, digest, err)
	}
	f.Close()
}

func TestNothingCarriedFallsBackToTheUpstreamOnlyWhenOneIsSet(t *testing.T) {
	twoSources(t)
	oldUp := UpstreamDist
	t.Cleanup(func() { UpstreamDist = oldUp })

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/nowhere.test/linux/x86-64/versions.txt") {
			_, _ = w.Write([]byte("2.5.0\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer up.Close()

	UpstreamDist = up.URL
	vs, fromRegistry, err := versionsForSourced("nowhere.test", "linux", "x86-64")
	if err != nil || len(vs) != 1 || vs[0].Raw != "2.5.0" || fromRegistry {
		t.Errorf("with an upstream: vs=%v registry=%v err=%v", vs, fromRegistry, err)
	}

	UpstreamDist = "none"
	if vs, _, err := versionsForSourced("nowhere.test", "linux", "x86-64"); err == nil || len(vs) != 0 {
		t.Errorf("with no upstream: vs=%v err=%v", vs, err)
	}
}

func TestTheGlibcFloorIsReadFromWhicheverSourceCarriesIt(t *testing.T) {
	_, zpkg, _, fr := twoSourcesFR(t)
	_, err := zpkg.PushWithReferrersAnnotated(GlibcProject, "2.40.0", "linux", "x86-64",
		makeGzTarball("glibc"), ".tar.gz", nil, map[string]string{GlibcMinKernelAnnotation: "4.19"})
	if err != nil {
		t.Fatal(err)
	}
	// Carried by the second source only: the first answers "unknown repository".
	if got, err := glibcMinKernelOf("2.40.0", "linux", "x86-64"); err != nil || got != "4.19" {
		t.Errorf("glibcMinKernelOf = %q, %v", got, err)
	}
	// A source that cannot be read is an error, not a reason to ask the next.
	failNamespace(fr, "run/packages")
	if got, err := glibcMinKernelOf("2.40.0", "linux", "x86-64"); err == nil {
		t.Errorf("glibcMinKernelOf past an unreadable source = %q", got)
	}
	// One source, not carried: the plain error, as before.
	failNamespace(fr, "nothing-here")
	DistBase, DistExtra = fr.base("run/packages"), nil
	resetOCICache()
	if _, err := glibcMinKernelOf("2.40.0", "linux", "x86-64"); err == nil {
		t.Error("a glibc the only source lacks reported no error")
	}
	// A static HTTP dist carries no annotations: unknown, not an error.
	DistBase = "https://dist.example.invalid"
	if got, err := glibcMinKernelOf("2.40.0", "linux", "x86-64"); err != nil || got != "" {
		t.Errorf("http dist: %q, %v", got, err)
	}
}

func TestABIAnnotationsComeFromTheFirstSourceThatAnswers(t *testing.T) {
	stage, zpkg, _ := twoSources(t)
	push := func(c *OCIClient, project, soname string) {
		t.Helper()
		_, err := c.PushWithReferrersAnnotated(project, "1.0.0", "linux", "x86-64",
			makeGzTarball(project), ".tar.gz", nil, map[string]string{ABIProvidesAnnotation: soname})
		if err != nil {
			t.Fatal(err)
		}
	}
	push(stage, "inrun.test", "libinrun.1.so")
	push(zpkg, "published.test", "libpublished.2.so")
	for project, want := range map[string]string{"inrun.test": "libinrun.1.so", "published.test": "libpublished.2.so"} {
		got := abiAnnotations(project, "1.0.0", "linux", "x86-64")
		if got[ABIProvidesAnnotation] != want {
			t.Errorf("%s: annotations = %v, want %s", project, got, want)
		}
	}
	if got := abiAnnotations("nowhere.test", "1.0.0", "linux", "x86-64"); got != nil {
		t.Errorf("a project in no source has annotations: %v", got)
	}
}
