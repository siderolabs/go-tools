// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v4"
)

var validateCmd = &cobra.Command{
	Use:   "validate <image>",
	Short: "Validate root filesystem extensions.",
	Long:  `Validate root filesystem extensions.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return validate()
	},
}

var validateFlags struct {
	image              string
	exceptions         string
	generateExceptions string
	platform           string
}

func init() {
	validateCmd.Flags().StringVar(&validateFlags.image, "image", "", "The image reference of the extension image manifest to validate.")
	validateCmd.Flags().StringVar(&validateFlags.exceptions, "exceptions", "", "Path to exceptions.yaml file listing allowed duplicate files per extension.")
	validateCmd.Flags().StringVar(&validateFlags.generateExceptions, "generate-exceptions", "", "Write all current duplicates to the given path as exceptions.yaml and exit without error.")
	validateCmd.Flags().StringVar(&validateFlags.platform, "platform", "linux/amd64", "The platform to use when fetching images (e.g., linux/amd64).")

	rootCmd.AddCommand(validateCmd)
}

// exceptionEntry declares a set of images that are allowed to share a set of files.
type exceptionEntry struct {
	Images []string `yaml:"images"`
	Files  []string `yaml:"files"`
}

type exceptionList []exceptionEntry

// allows returns true if the given file being shared among owners is covered by an exception entry.
// The entry's images must exactly match the owners set.
// File patterns support filepath.Match glob syntax (e.g. rootfs/usr/lib/modules/*/).
func (e exceptionList) allows(file string, owners []string) bool {
	for _, entry := range e {
		if !slices.Equal(sortedCopy(entry.Images), sortedCopy(owners)) {
			continue
		}

		for _, pattern := range entry.Files {
			matched, err := filepath.Match(pattern, file)
			if err == nil && matched {
				return true
			}
		}
	}

	return false
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)

	return c
}

//nolint:gocognit,gocyclo,cyclop,maintidx
func validate() error {
	if validateFlags.image == "" {
		return fmt.Errorf("image flag is required")
	}

	ref, err := name.ParseReference(validateFlags.image)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %w", err)
	}

	platform, err := v1.ParsePlatform(validateFlags.platform)
	if err != nil {
		return fmt.Errorf("failed to parse platform: %w", err)
	}

	img, err := remote.Image(ref, remote.WithPlatform(*platform))
	if err != nil {
		return fmt.Errorf("failed to fetch image: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get image layers: %w", err)
	}

	var imageDigests bytes.Buffer

	for _, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			return fmt.Errorf("failed to read layer: %w", err)
		}

		defer rc.Close() //nolint:errcheck

		tr := tar.NewReader(rc)

		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}

			if err != nil {
				return fmt.Errorf("failed to read tar entry: %w", err)
			}

			if filepath.Base(hdr.Name) == "image-digests" {
				if _, err = io.Copy(&imageDigests, tr); err != nil {
					return fmt.Errorf("failed to read image-digests: %w", err)
				}

				break
			}
		}
	}

	imageFiles := map[string][]string{}

	scanner := bufio.NewScanner(&imageDigests)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		fmt.Printf("Processing image reference: %s\n", line)

		ref, err := name.ParseReference(line)
		if err != nil {
			return fmt.Errorf("failed to parse image reference %q: %w", line, err)
		}

		extImg, err := remote.Image(ref, remote.WithPlatform(*platform))
		if err != nil {
			return fmt.Errorf("failed to fetch image %q: %w", line, err)
		}

		cf, err := extImg.ConfigFile()
		if err != nil {
			return fmt.Errorf("failed to get config for %q: %w", line, err)
		}

		if cf.Architecture != platform.Architecture || cf.OS != platform.OS {
			return fmt.Errorf("%s: platform %s/%s does not match requested %s", line, cf.OS, cf.Architecture, validateFlags.platform)
		}

		extLayers, err := extImg.Layers()
		if err != nil {
			return fmt.Errorf("failed to get layers for %q: %w", line, err)
		}

		var files []string

		for _, layer := range extLayers {
			rc, err := layer.Uncompressed()
			if err != nil {
				return fmt.Errorf("failed to read layer for %q: %w", line, err)
			}

			defer rc.Close() //nolint:errcheck

			tr := tar.NewReader(rc)

			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}

				if hdr.Typeflag == tar.TypeDir {
					continue
				}

				if err != nil {
					return fmt.Errorf("failed to read tar entry for %q: %w", line, err)
				}

				switch name := hdr.Name; {
				case strings.HasPrefix(filepath.Base(name), "modules."):
					continue
				case name == "manifest.yaml":
					continue
				}

				files = append(files, hdr.Name)
			}
		}

		imageFiles[ref.Context().Name()] = files
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan image digests: %w", err)
	}

	// Build a map of file path -> list of images that contain it.
	fileOwners := map[string][]string{}

	for img, files := range imageFiles {
		for _, file := range files {
			fileOwners[file] = append(fileOwners[file], img)
		}
	}

	// Collect duplicates (files present in more than one extension).
	duplicates := map[string][]string{}

	for file, owners := range fileOwners {
		if len(owners) > 1 {
			duplicates[file] = owners
		}
	}

	// Generate exceptions.yaml from current duplicates and exit.
	if validateFlags.generateExceptions != "" {
		// Group files by their sorted owner set so each unique overlap becomes one entry.
		groups := map[string]*exceptionEntry{}

		for file, owners := range duplicates {
			key := strings.Join(sortedCopy(owners), "\x00")

			entry, ok := groups[key]
			if !ok {
				entry = &exceptionEntry{Images: sortedCopy(owners)}
				groups[key] = entry
			}

			entry.Files = append(entry.Files, file)
		}

		var generated exceptionList

		for _, entry := range groups {
			slices.Sort(entry.Files)
			generated = append(generated, *entry)
		}

		slices.SortFunc(generated, func(a, b exceptionEntry) int {
			return strings.Compare(a.Images[0], b.Images[0])
		})

		out, err := yaml.Marshal(generated)
		if err != nil {
			return fmt.Errorf("failed to marshal exceptions: %w", err)
		}

		if err = os.WriteFile(validateFlags.generateExceptions, out, 0o644); err != nil {
			return fmt.Errorf("failed to write exceptions file: %w", err)
		}

		fmt.Printf("Wrote exceptions to %s\n", validateFlags.generateExceptions)

		return nil
	}

	// Load exceptions if provided.
	var exceptions exceptionList

	if validateFlags.exceptions != "" {
		data, err := os.ReadFile(validateFlags.exceptions)
		if err != nil {
			return fmt.Errorf("failed to read exceptions file: %w", err)
		}

		if err = yaml.Unmarshal(data, &exceptions); err != nil {
			return fmt.Errorf("failed to parse exceptions file: %w", err)
		}
	}

	// Filter out excepted duplicates, grouping remaining violations by owner set.
	violationGroups := map[string]*exceptionEntry{}

	for file, owners := range duplicates {
		if exceptions.allows(file, owners) {
			continue
		}

		key := strings.Join(sortedCopy(owners), "\x00")

		entry, ok := violationGroups[key]
		if !ok {
			entry = &exceptionEntry{Images: sortedCopy(owners)}
			violationGroups[key] = entry
		}

		entry.Files = append(entry.Files, file)
	}

	if len(violationGroups) == 0 {
		fmt.Println("No duplicate files found.")

		return nil
	}

	var violations []exceptionEntry

	for _, entry := range violationGroups {
		slices.Sort(entry.Files)
		violations = append(violations, *entry)
	}

	slices.SortFunc(violations, func(a, b exceptionEntry) int {
		return strings.Compare(a.Images[0], b.Images[0])
	})

	fmt.Println("Duplicate files found:")

	for _, entry := range violations {
		fmt.Println("- images:")

		for _, img := range entry.Images {
			fmt.Printf("    - %s\n", img)
		}

		fmt.Println("  files:")

		for _, file := range entry.Files {
			fmt.Printf("    - %s\n", file)
		}
	}

	return fmt.Errorf("duplicate files found")
}
