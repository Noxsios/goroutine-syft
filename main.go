package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
)

var images = []string{
	"nginx:1.24.0-alpine3.17",
	"node:20-alpine3.17",
	"postgres:alpine3.17",
	"httpd:alpine3.17",
}

func main() {
	cacheDir, err := filepath.Abs("./cache")
	if err != nil {
		log.Fatal(err)
	}
	imagesDir, err := filepath.Abs("./images")
	if err != nil {
		log.Fatal(err)
	}
	sbomsDir, err := filepath.Abs("./sboms")
	if err != nil {
		log.Fatal(err)
	}

	repeatedLayers := map[string]int{}

	imageTags := map[string]v1.Hash{}

	for _, image := range images {
		var img v1.Image

		img, err := crane.Pull(image)
		if err != nil {
			log.Fatal(err)
		}

		img = cache.Image(img, cache.NewFilesystemCache(cacheDir))

		layers, err := img.Layers()
		if err != nil {
			log.Fatal(err)
		}

		for _, layer := range layers {
			digest, err := layer.Digest()
			if err != nil {
				log.Fatal(err)
			}
			repeatedLayers[digest.String()]++
		}

		if err := crane.SaveOCI(img, imagesDir); err != nil {
			log.Fatal(err)
		}

		digest, err := img.Digest()
		if err != nil {
			log.Fatal(err)
		}
		tag := strings.Split(image, ":")[1]
		imageTags[tag] = digest
	}

	for digest, count := range repeatedLayers {
		if count > 1 {
			log.Printf("Layer %q is repeated %d times", digest, count)
		}
	}

	for tag, _ := range imageTags {
		src, location, err := image.DetectSource(imagesDir)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Detected source %q for %q", src, location)

		cfg := source.StereoscopeImageConfig{
			Reference: imagesDir,
			From:      src,
		}

		syftSource, err := source.NewFromStereoscopeImage(cfg)
		if err != nil {
			log.Fatal(err)
		}

		catalog, relationships, distro, err := syft.CatalogPackages(syftSource, cataloger.DefaultConfig())
		if err != nil {
			log.Fatal(err)
		}

		artifact := sbom.SBOM{
			Descriptor: sbom.Descriptor{
				Name: "zarf",
			},
			Artifacts: sbom.Artifacts{
				Packages:          catalog,
				LinuxDistribution: distro,
			},
			Relationships: relationships,
		}

		data, err := syft.Encode(artifact, syft.FormatByID(syft.JSONFormatID))
		if err != nil {
			log.Fatal(err)
		}

		f, err := os.Create(filepath.Join(sbomsDir, tag+".json"))
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			log.Fatal(err)
		}
		log.Printf("Wrote %q", f.Name())
	}

}
