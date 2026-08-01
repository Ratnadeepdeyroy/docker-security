package connector

import (
	"context"
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/report"
)

// SARIFFile writes the report as a SARIF file, e.g. for upload as a CI artifact
// or to GitHub code scanning.
type SARIFFile struct {
	Path string
}

// NewSARIFFile builds a SARIF-file connector targeting path.
func NewSARIFFile(path string) *SARIFFile { return &SARIFFile{Path: path} }

func (f *SARIFFile) Name() string { return "sarif-file" }

func (f *SARIFFile) Send(_ context.Context, r *engine.Report) error {
	out, err := os.Create(f.Path)
	if err != nil {
		return err
	}
	defer out.Close()
	return report.SARIF{}.Format(out, r)
}
