/*
The tar.gz functionality has been inspired the following resources:

http://stackoverflow.com/a/40003617
http://blog.ralch.com/tutorial/golang-working-with-tar-and-gzip/
https://medium.com/@skdomino/taring-untaring-files-in-go-6b07cf56bc07

All credit for these functions goes to the authors of the above posts.
*/
package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tarGz takes a source and variable writers and walks 'source' writing each file
// found to the tar writer; the purpose for accepting multiple writers is to allow
// for multiple outputs (for example a file, or md5 hash)
func tarGz(src string, writers ...io.Writer) error {
	// ensure the src actually exists before trying to tar it
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("Unable to tar files - %v", err.Error())
	}

	mw := io.MultiWriter(writers...)

	gzw := gzip.NewWriter(mw)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(src)
	}

	// walk path
	return filepath.Walk(src, func(file string, fi os.FileInfo,
		err error) error {

		// return on any error
		if err != nil {
			fmt.Println(err)
			fmt.Println("\nYou seem to have encountered a file " +
				"system error.\nPlease file a bug report to" +
				" help me investigate it.\n")
			return err
		}

		// We include symlinks as is and won't dereference them
		var link string
		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			if link, err = os.Readlink(src); err != nil {
				return err
			}
		}

		// create a new dir/file header
		header, err := tar.FileInfoHeader(fi, link)

		if err != nil {
			return err
		}
		// If there is no basedir, leave the filename as it is, else
		// update the name to reflect the desired destination.
		if baseDir != "" {
			header.Name = filepath.Join(baseDir,
				strings.TrimPrefix(file, src))
		}

		// write the header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// return on directories and symlinks since there will be no
		// content to tar
		if !fi.Mode().IsRegular() {
			return nil
		}

		// open files for taring
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer func() {
			if err := f.Close(); err != nil {
				panic(err)
			}
		}()

		// copy file data into tar writer
		if _, err := io.Copy(tw, f); err != nil {
			return err
		}
		return nil
	})
}

// UntarGz takes a destination path and a reader; a tar reader loops over the
// tarfile creating the file structure at 'dst' along the way, and writing any
// files
func untarGz(dst string, r io.Reader) error {

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		target := filepath.Join(dst, header.Name)

		// check the file type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		// os.Stat() won't work on symlinks, so we try to create it anyway.
		case tar.TypeSymlink:
			err := os.Symlink(header.Name, target)
			if os.IsExist(err) {
				fmt.Println("Symlink " + target +
					" already exists. Skipping.")
			} else if err != nil {
				fmt.Println(err)
				return err
			}

		// if it's a file create it
		case tar.TypeReg:
			f, err := os.OpenFile(target,
				os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			// Defer closure in case anything fails
			defer f.Close()

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			// Close the file explicitly.
			// Deferred calls execute too late and for large
			// numbers of files we'd get a "too many files open"
			// panic before the function can return and close
			// the files.
			f.Close()
		}
	}
}
