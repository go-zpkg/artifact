package artifact

import (
	"errors"
	"testing"
)

const goPkgxReg = "oci://ghcr.io/go-pkgx/packages"

func resetPromotionState(t *testing.T) {
	t.Helper()
	oldB, oldX, oldP := DistBase, DistExtra, promotionSource
	t.Cleanup(func() { DistBase, DistExtra, promotionSource = oldB, oldX, oldP; resetOCICache() })
	promotionSource = ""
}

// A promotion may READ the go-pkgx registry it was told to copy from.
func TestAPromotionSourceInGoPkgxIsReadable(t *testing.T) {
	resetPromotionState(t)
	SetPromotionSource(goPkgxReg + "/")
	if DistBase != goPkgxReg || len(DistExtra) != 0 {
		t.Fatalf("DistBase=%q DistExtra=%q", DistBase, DistExtra)
	}
	if _, err := distSources(); err != nil {
		t.Fatalf("the promotion source is refused: %v", err)
	}
	if _, err := ociClientForDist(); errors.Is(err, ErrClosedDistRegistry) {
		t.Fatalf("the client for the promotion source is refused: %v", err)
	}
}

// ...and nothing else may: the dependency list, a second go-pkgx spelling, an
// extra source, or the environment.
func TestGoPkgxStaysRefusedAsADependencySourceDuringAPromotion(t *testing.T) {
	for name, set := range map[string]func(){
		"no promotion source: DistBase": func() { DistBase, DistExtra = goPkgxReg, nil },
		"ZPKG_DIST after a promotion source is set": func() {
			SetPromotionSource(goPkgxReg)
			applyEnv(func(k string) string {
				if k == "ZPKG_DIST" {
					return goPkgxReg
				}
				return ""
			})
		},
		"go-pkgx as a second source": func() {
			SetPromotionSource(goPkgxReg)
			DistExtra = []string{goPkgxReg}
		},
		"a different go-pkgx repository": func() {
			SetPromotionSource(goPkgxReg)
			DistBase = "oci://ghcr.io/go-pkgx/other"
		},
		"go-pkgx first, the promotion source elsewhere": func() {
			SetPromotionSource("oci://ghcr.io/go-zpkg/packages")
			DistBase, DistExtra = "oci://ghcr.io/go-zpkg/packages", []string{goPkgxReg}
		},
	} {
		t.Run(name, func(t *testing.T) {
			resetPromotionState(t)
			set()
			if _, err := distSources(); !errors.Is(err, ErrClosedDistRegistry) {
				t.Fatalf("distSources: %v, want the closed-registry refusal", err)
			}
			if DistBase == goPkgxReg && promotionSource != goPkgxReg {
				if _, err := ociClientForDist(); !errors.Is(err, ErrClosedDistRegistry) {
					t.Fatalf("ociClientForDist: %v, want the closed-registry refusal", err)
				}
			}
		})
	}
}

// CheckDistSource itself never learns the exception: it is the rule for a
// dependency source, and SetPromotionSource must not change it.
func TestCheckDistSourceIgnoresThePromotionSource(t *testing.T) {
	resetPromotionState(t)
	SetPromotionSource(goPkgxReg)
	if err := CheckDistSource(goPkgxReg); !errors.Is(err, ErrClosedDistRegistry) {
		t.Fatalf("CheckDistSource accepted go-pkgx after SetPromotionSource: %v", err)
	}
}
