// Copyright 2017 Manuel Iwansky.
// This source code may be used according to a BSD-style license
// that is stated in the LICENSE file.

/*
gdzip is a tool to compress and encrypt files. The design goal
is to use simple and robust implementations of modern and secure
encryption algorithms, at the time of writing.

Internally, the given files and/or folders ar stored as tar.gz archives.
The data are split into chunks while encrypting, and encryption is done
done using AES256-GCM and/or ChaCha20-Poly1305. All this happens in RAM,
so no temporary files will be used.
Keys are generated using the scrypt key derivation function.
The encrypted files provide no information about their contents or
their contents' filenames. Encrypted files may be safely renamed and even
the extension may be altered or left out.

Possible use cases:
-  storing sensitive data locally and keeping their contents safe from
  prying eyes.
-  encrypting a directory or file and sending it via email to a recipient
  who cannot handle the intricacies of a public key infrastructure
  (i.e. S/MIME or PGP), replacing password-secured ZIP files which are to
  be considered insecure and unsafe (for example, password-secured ZIP
  files do not hide the filenames of their content)
-  Corporate spam filters, nowadays, block suspicious content. There
  are justifiable reasons for that.
  However, as made clear in the use case above, there are valid reasons
  to share data in a convenient and reasonably secure way over an unsafe
  medium, like email. A new and rather obscure tool to share these data
  may shorten the time for those users until PKI is implemented in a way
  that is transparent to the user, standardized, and safe to use.

Use 'gdzip -h' to get basic usage information.
A detailed manual as well as a GUI are in the works.

The resulting encrypted file may be split into different files, e.g. to make
it possible to be sent via email, or to store it on a file system that does
not support large files (Fat16/32).
The splitting functionality is not implemented, yet. Until then, the user
can use her system's equivalent of the split(1) program for splitting, and
cat(1) to concatenate the files again before decrypting.
*/

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Some global variables. This way we avoid having to pass them
// to and from each and every function in which they are used.
var (
	// Variables that get filled by the flags:
	chunkLen         int64  // Maximum size of the chunks to encrypt
	encFile          string // The file to encrypt
	decFile          string // The file to decrypt
	destination      string // The destination path
	mode             uint8  // The cipher mode
	passphrase       []byte // The passphrase
	quiet            bool   // Whether to suppress verbose output
	scryptComplexity string // The complexity level for key derivation
	statusCode       int    // The status code on program termination
	// Variables to pass to the scrypt Key derivation function:
	scryptN int // N-factor for scrypt
	scryptR int // r-factor for scrypt
	scryptP int // p-factor for scrypt
	// The magic number. Do not change this unless you need to break
	// compatibility with other builds.
	magic = []byte{0xD0, 0x6E, 0xFA, 0xCE}
	// The first gobbledog file format version is 101 in HEX (0x65):
	fileVersion = []byte{0x65}
)

// Global constants. - Here be dragons. Better don't change anything.
// Some values have to do with encryption, and wrong values can either
// break the security, make your machine hang, or break this program
// completely.
const (
	// Default values for scrypt. Unless you *ABSOLUTELY* know what
	// you're doing, leave them as is. The higher values can be called
	// by using the "-scrypt" flag.
	defaultScryptN = 65536
	defaultScryptR = 16 // restricted to uint8 for now (max. 255)
	defaultScryptP = 4  // restricted to uint8 for now (max. 255)
	mediumScryptN  = 131072
	highScryptN    = 262144
	// The keylength:
	// 256 bits = 32 bytes. Chacha20 and AES256 use 256 bit keys.
	keyLength   = 32 // length in bytes. 32 is the only possible value.
	nonceLength = 12 // nonces for chacha20poly1305 are 12 bytes long.
	ivLength    = 12 // IVs for AES are 12 bytes long.
	// As of 2017, 32 bytes are generously large for a salt:
	saltLength = 32 // length in bytes. Restricted to uint8 (max 255)
	// Changing these will break this program, and and any binary-based
	// computations, for that matter:
	sixtyFourBit = 8   // 8 bytes are 64 bits.
	uint8Max     = 255 // highest value of an uint8
)

// main function.
func main() {
	// Parse the command line flags.
	parseFlags()

	if encFile != "" && decFile == "" {
		// encFile is set, encrypt it
		encrypt()
	} else if decFile != "" && encFile == "" {
		// decFile is set, decrypt it
		decrypt()
	} else {
		// It is unclear what the user wants.
		// Print an error message.
		printAmbiguityError()
	}

	os.Exit(statusCode)
}

// parseFlags interprets the command line flags.
func parseFlags() {
	chunkSizePtr := flag.Int64("chunksize", 4096, `the maximum size of`+
		` chunks to split the message into in
	kilobytes.
	Chunking makes sure that the whole message can be encrypted,
	even on systems with restricted RAM. The default is 4 MB.
	 - If in doubt, omit this flag to leave it at the default.
	Smaller files will be encrypted in one chunk.
	`)
	encryptPtr := flag.String("encrypt", "",
		"name of the file to encrypt\n")
	decryptPtr := flag.String("decrypt", "",
		"name of the file to decrypt\n")
	destPtr := flag.String("dest", "", `the destination path.
	Defaults to the current working directory, if not otherwise specified.
	`)
	modePtr := flag.Int("mode", 1, `the encryption mode.
	1 - AES256 with GCM
	2 - ChaCha20 with Poly1305
	3 - Cascade: AES256 -> ChaCha20
	4 - Cascade: ChaCha20 -> AES256
	`)
	passPtr := flag.String("passphrase", "", `the passphrase.
	CAUTION: this is meant for non-interactive usage only. When called
	from the shell, the passphrase will appear in your shell's history,
	which is a great security risk.
	Omit this flag to set the passphrase interactively.
	`)
	quietPtr := flag.Bool("quiet", false, "suppress verbose output\n")
	scryptPtr := flag.String("scrypt", "default", `the complexity level`+
		` for scrypt.
	Can be set to "default", "medium" or "high".
	The default is reasonably safe and more secure settings will
	slow down the key derivation considerably.
	`)
	flag.Parse()

	chunkLen = 1024 * *chunkSizePtr
	encFile = *encryptPtr
	decFile = *decryptPtr
	destination = *destPtr
	mode = uint8(*modePtr)
	passphrase = []byte(*passPtr)
	quiet = *quietPtr
	// set the security level
	scryptComplexity = *scryptPtr
	if scryptComplexity == "default" {
		scryptN = defaultScryptN
	} else if scryptComplexity == "medium" {
		scryptN = mediumScryptN
	} else if scryptComplexity == "high" {
		scryptN = highScryptN
	} else {
		scryptN = defaultScryptN
		fmt.Println("No valid complexity level given. Using default.")
	}
	scryptP = defaultScryptP
	scryptR = defaultScryptR
}

// encrypt compresses a file or directory and encrypts it.
func encrypt() {
	if destination == "" {
		path, err := os.Getwd()
		check(err)
		destination = path + string(os.PathSeparator) +
			filepath.Base(encFile) + ".gdz"
	} else {
		sep := ""
		if string(destination[len(destination)-1]) != string(
			os.PathSeparator) {
			sep = string(os.PathSeparator)
		}
		destination = destination + sep + filepath.Base(encFile) + ".gdz"
	}

	if _, err := os.Stat(destination); err == nil {
		fmt.Printf("\n%s already exists. Overwrite? (yes/No): ",
			destination)
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		if !strings.EqualFold("y", string(text[0])) {
			fmt.Println("File not overwritten. Aborting.")
			statusCode = 4
			return
		}
	}

	// Create the file to write our output to.
	outFile, err := os.Create(destination)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	check(err)
	defer func() {
		if err := outFile.Close(); err != nil {
			panic(err)
		}
	}()

	// When encrypting, we want to check the user input for typos,
	// so we pass decrypt = false to getPassphrase().
	encrypting := true
	// Get the encryption passphrase from the user, if it is not already
	// set by the flag:
	if len(passphrase) == 0 {
		passphrase = getPassphrase(encrypting)
	}

	// Generate the encryption key:
	//
	// First we need a salt.
	salt := getRandomBytes(saltLength)
	//
	// Create a key from the passphrase.
	// The keylengths for AES256 and Chacha20 are 256 bits, respectively.
	logMsg("\n\nCalculating the encryption key. This may take a while... ")
	chacha20Key, aes256Key := generateKey(salt, passphrase)
	// We don't need the passphrase anymore, so we overwrite it with zeros.
	// This will not get rid of any copies the garbage collector might have
	// made, but it's the least we can do for now. There are efforts to
	// make golang's memory usage more interfaceable, but they are not to
	// be regarded stable, yet. (see github.com/libeclipse/memguard, for
	// an example)
	eraseSlice(passphrase)
	logMsg("done.\n")

	// Create the public header
	messageHeader := assembleHeader(salt)

	// The writer to write our output on disk:
	fileWriter := bufio.NewWriter(outFile)

	// Write the public header into the beginning of the file:
	bytesWritten, err := fileWriter.Write(messageHeader)
	check(err)

	// The TarGz function expects a writer, but to further process
	// its output, we need a reader. We can lay an io.Pipe to get
	// a reader interface at the end of the writer:
	tarReader, tarWriter := io.Pipe()

	// Writing without a reader will deadlock, so we put the writer in the
	// background via a goroutine:
	go func() {
		// defer closure of the writer
		defer tarWriter.Close()

		// Make a tar.gz of the input file and write it into our
		// tarwriter:
		tarErr := tarGz(encFile, tarWriter)
		check(tarErr)
	}()

	// Maps to store string conversions of the nonces/IVs for checking
	// for duplicates. Because we are in control of the whole message,
	// we can generate a random nonce/IV for each encrypted chunk.
	// Although collisions are unlikely, they must not happen, so
	// we check for duplicates as IVs/nonces are created.
	// (Duplicate use of an IV/nonce with the same key must absolutely,
	// positively NOT happen. Otherwise the message could be cracked)
	nonceStringMap := make(map[string]bool)
	ivStringMap := make(map[string]bool)

	var now, timeDiff int64
	logMsg("\nEncrypting...\n\n")
	start := time.Now().UnixNano() / int64(time.Millisecond)
	timeLast := start
	sandClockIndex := 0

	// This is the main loop to handle compression/encryption:
	for {
		// Display a spinner and write the progress when verbose
		now = time.Now().UnixNano() / int64(time.Millisecond)
		timeDiff = now - timeLast
		timeLast, sandClockIndex = displayStatus(encrypting, now,
			timeDiff, timeLast, bytesWritten, sandClockIndex)

		// read from the tarReader into chunkBuf
		chunkBuf, eofReached := readTar(tarReader)

		// Get a random nonce and/or IV and put their string
		// representation into a hash table
		currentIV, currentNonce := getNonce(ivStringMap, nonceStringMap)

		// Encrypt our buffer's contents:
		chunkBuf = encryptBuffer(chunkBuf, aes256Key, chacha20Key,
			currentIV, currentNonce)

		// Get the chunk's final length and prepend it to the chunk:
		currentChunkLen := make([]byte, sixtyFourBit)
		binary.BigEndian.PutUint64(currentChunkLen,
			uint64(len(chunkBuf)))
		chunkBuf = append(currentChunkLen, chunkBuf...)

		// Write the encrypted chunk
		bw, err := fileWriter.Write(chunkBuf)
		if err != nil {
			panic(err)
		}

		bytesWritten += bw // add to the total of bytes written

		if eofReached {
			break // We're finished. Break out of the loop.
		}
	}

	// Overwrite the keys with zeros:
	eraseSlice(aes256Key)
	eraseSlice(chacha20Key)

	// Flush and close the fileWriter.
	if err = fileWriter.Flush(); err != nil {
		panic(err)
	}

	logMsg("\rDone." + strings.Repeat(" ", 60) + "\n")
	logMsg("Encrypted file: " + destination + "\n")
	logStatus(start, bytesWritten, encrypting)
	statusCode = 0

	return
}

// logStatus prints a final one-line report when verbose.
func logStatus(start int64, bytesWritten int, encrypt bool) {
	var op string
	if encrypt {
		op = "written"
	} else {
		op = "read"
	}

	if !quiet {
		end := time.Now().UnixNano() / int64(time.Millisecond)
		duration := end - start
		fmt.Printf(
			"%d bytes (%0.3f MB) "+op+" in %d ms (%0.2f seconds)\n",
			bytesWritten, float32(bytesWritten)/(1024*1024),
			duration, float32(duration)/1000)
	}
}

// eraseSlice overwrites a byte slice with zeros
func eraseSlice(s []byte) {
	for i := range s {
		s[i] = byte(0)
	}
}

// readTar reads from the tar reader into a buffer of size chunkLen
func readTar(tarReader io.Reader) ([]byte, bool) {
	// Every iteration of the loop starts with an unused buffer.
	// We need to keep track of how many bytes we have actually
	// written into the buffer, because most often, the buffer
	// will be larger than the last chunk of the file.
	bytesPerBuffer := 0
	// Wether we have reached EOF, yet:
	eofReached := false
	// chunkBuf is the buffer to store and process our chunks.
	chunkBuf := make([]byte, chunkLen)

	// Occasionally, the pipe's tarReader will return zero bytes
	// and no error (nil). We keep reading from it until the buffer
	// is full or EOF has been reached.
	for bytesPerBuffer < len(chunkBuf) {
		// Read from the tarReader.
		// br: current bytes read from the tarReader
		br, err := tarReader.Read(chunkBuf[bytesPerBuffer:])
		bytesPerBuffer += br // add br to the total/buffer
		if err == io.EOF {
			// We have reached the tarReader's EOF.
			eofReached = true
			// We won't get any more bytes from the
			// reader, so we have to continue without
			// a full buffer:
			break
		} else if err != nil {
			// Any other error is inacceptable.
			panic(err)
		}
	}

	// resize chunkBuf, if necessary
	return chunkBuf[:bytesPerBuffer], eofReached
}

// getNonce returns unique nonces and IVs
func getNonce(ivStringMap map[string]bool, nonceStringMap map[string]bool) (
	[]byte, []byte) {
	currentIV := make([]byte, ivLength)
	currentNonce := make([]byte, nonceLength)
	var nonceString, ivString string
	//
	// For modes 1, 3 and 4 we need IVs
	if mode == 1 || mode == 3 || mode == 4 {
		// Read from crypto/rand into the slice
		_, err := io.ReadFull(rand.Reader, currentIV[:])
		check(err)
		// Get a string representation of the IV for the
		// hashmap.
		// a []byte slice is not comparable in a hash map, but
		// a string can be compared with "==".
		ivString = string(currentIV[:])
		//
		// Check whether it exists in nonceStringMap.
		//
		// The following while loop's condition will almost
		// never be true, but when it is, we have to eliminate
		// the duplicate before it can be used as a nonce.
		for ivStringMap[ivString] == true {
			// Get a new nonce.
			_, err := io.ReadFull(rand.Reader, currentIV[:])
			check(err)
			// Reassign the string.
			ivString = string(currentIV[:])
			logMsg("\nDuplicate IV found." +
				"\nIf this happens often," +
				" your system's random" +
				" number generator might be broken.")
		}
		//
		// Now that we have a unique IV, put it into the map.
		ivStringMap[ivString] = true
	}
	// For modes 2, 3 and 4 we need nonces.
	if mode == 2 || mode == 3 || mode == 4 {
		_, err := io.ReadFull(rand.Reader, currentNonce[:])
		check(err)
		// Same as before, just with nonces.
		nonceString = string(currentNonce[:])
		for nonceStringMap[nonceString] == true {
			_, err := io.ReadFull(rand.Reader,
				currentNonce[:])
			check(err)
			// Reassign the string.
			nonceString = string(currentNonce[:])
			logMsg("\nDuplicate nonce found." +
				"\nIf this happens often," +
				" your system's random" +
				" number generator might be broken.")
		}
		// Put the nonce into the map.
		nonceStringMap[nonceString] = true
	}
	return currentIV, currentNonce
}

// decrypt a gdz archive and write its contents after untargzing to disk.
func decrypt() {
	// Open the input file for reading.
	logMsg("Reading file: " + decFile + "\n")
	inFile, err := os.Open(decFile)
	check(err)
	// Defer closure of the file.
	defer func() {
		err := inFile.Close()
		check(err)
	}()

	// Read the header
	bytesRead, salt := readHeader(inFile)

	// If the header was wrong, return:
	switch statusCode {
	case 3: // wrong magic number - return with error
		logMsg("\nThis is not a gdzip encrypted file. \n" +
			"Either the header and file is corrupt or the file" +
			" is invalid.\nAborting.\n")
		fmt.Println("Error: not a gdz file")
		return

	case 4: // unknown version - return with error:
		logMsg("\nThis file seems to be encrypted with a newer" +
			"version of gdzip. Please get the most recent version" +
			"and try again.\n")
		fmt.Println("Error: unknown file version")
		return
	}

	if destination == "" {
		path, err := os.Getwd()
		check(err)
		destination = path
	} else {
		sep := ""
		if string(destination[len(destination)-1]) != string(os.PathSeparator) {
			sep = string(os.PathSeparator)
		}
		destination = destination + sep
	}

	// Get the passphrase
	encrypting := false
	passphrase := getPassphrase(encrypting)

	// Generate the decryption key
	logMsg("\n\nCalculating the decryption key. This may take a while... ")
	chacha20Key, aes256Key := generateKey(salt, passphrase)
	logMsg("done.\n")

	// clear the passphrase
	eraseSlice(passphrase)

	// Analogous to encrypting, we need an io.Pipe for the UntarGz
	// function.
	// Because it may need some time to write its last bytes, we have
	// to wait for it to finish, so we add it to a WaitGroup.
	untarReader, untarWriter := io.Pipe()
	var wg sync.WaitGroup // Initialize a WaitGroup.
	wg.Add(1)             // Add one goroutine to the WaitGroup.
	go func() {
		defer wg.Done() // Tell the WaitGroup that we're done.

		// untar the stream and write it to dest.
		untarErr := untarGz(destination, untarReader)
		if untarErr != io.EOF {
			check(untarErr)
		}
		defer untarReader.Close()
	}()

	// Whether EOF has been reached by the file Reader:
	eofReached := false

	var now, timeDiff int64
	logMsg("\nDecrypting...\n\n")
	start := time.Now().UnixNano() / int64(time.Millisecond)
	timeLast := start
	sandClockIndex := 0

	// Decryption is handled in the following loop
	for {
		// Display a spinner and write the progress when verbose
		now = time.Now().UnixNano() / int64(time.Millisecond)
		timeDiff = now - timeLast
		timeLast, sandClockIndex = displayStatus(encrypting, now, timeDiff,
			timeLast, bytesRead, sandClockIndex)

		// Read the the next chunk's length.
		// When there are no more chunks, we get an EOF from
		// the reader, which is our signal to stop.
		currentChunkLenBytes := make([]byte, sixtyFourBit)
		br, err := inFile.Read(currentChunkLenBytes)
		if err == io.EOF {
			eofReached = true
		} else {
			check(err)
		}

		// As soon as we don't get any more bytes from the reader,
		// we're finished and have to leave the loop.
		if eofReached && br == 0 {
			fmt.Println(bytesRead)
			if err = untarWriter.Close(); err != nil {
				panic(err)
			}
			// Wait for the UntarGz writer to finish:
			wg.Wait()
			// We're done. Break out of the loop:
			break
		}

		currentChunkLen := binary.BigEndian.Uint64(currentChunkLenBytes)
		bytesRead += br

		// Make a fresh buffer.
		chunkBuf := make([]byte, int(currentChunkLen))

		// Read the ciphertext into the buffer.
		br, err = inFile.Read(chunkBuf)
		check(err)
		bytesRead += br

		// Decrypt the current chunk.
		chunkBuf = decryptBuffer(chunkBuf, aes256Key, chacha20Key)

		// Write the decrypted chunk to the io.Pipe for
		// untaring/gunzipping.
		_, err = untarWriter.Write(chunkBuf)
		check(err)
	}

	// Overwrite the keys
	eraseSlice(aes256Key)
	eraseSlice(chacha20Key)

	logMsg("\rDone.                                                            \n")
	logMsg("Destination: " + destination + "\n")
	logStatus(start, bytesRead, encrypting)

	statusCode = 0
	return
}

// displayStatus
func displayStatus(encrypt bool, now, timeDiff, timeLast int64, br, idx int) (
	int64, int) {
	sandClock := []string{`|`, `/`, `-`, `\`}
	var state string

	if encrypt {
		state = "written"
	} else {
		state = "read"
	}

	if !quiet {
		timeDiff = now - timeLast
	}
	if !quiet && timeDiff > 250 {
		fmt.Printf("\r") // Put the cursor back to the left.
		fmt.Printf(sandClock[idx]+" Please wait."+
			" Bytes "+state+": %d  (%0.3f MB)",
			br,
			float32(br)/(1024.0*1024.0))
		if idx == 3 {
			idx = 0
		} else {
			idx++
		}
		timeLast = now
	}
	return timeLast, idx
}

// encryptBuffer is a wrapper to encrypt a chunk buffer
func encryptBuffer(chunkBuf, aes256Key, chacha20Key, currentIV,
	currentNonce []byte) []byte {
	switch mode {
	case 1:
		chunkBuf = encryptAesGcm(aes256Key,
			currentIV, chunkBuf)
	case 2:
		chunkBuf = encryptChacha20Poly1305(
			chacha20Key, currentNonce,
			chunkBuf)
	case 3:
		chunkBuf = encryptAesGcm(aes256Key,
			currentIV, chunkBuf)
		chunkBuf = encryptChacha20Poly1305(
			chacha20Key, currentNonce,
			chunkBuf)
	case 4:
		chunkBuf = encryptChacha20Poly1305(
			chacha20Key, currentNonce,
			chunkBuf)
		chunkBuf = encryptAesGcm(aes256Key,
			currentIV, chunkBuf)
	}
	return chunkBuf
}

// decryptBuffer is a wrapper to decrypt a chunk buffer
func decryptBuffer(chunkBuf, aes256Key, chacha20Key []byte) []byte {
	switch mode {
	case 1:
		chunkBuf = decryptAesGcm(aes256Key, chunkBuf)
	case 2:
		chunkBuf = decryptChacha20Poly1305(chacha20Key,
			chunkBuf)
	case 3:
		chunkBuf = decryptChacha20Poly1305(chacha20Key,
			chunkBuf)
		chunkBuf = decryptAesGcm(aes256Key, chunkBuf)
	case 4:
		chunkBuf = decryptAesGcm(aes256Key, chunkBuf)
		chunkBuf = decryptChacha20Poly1305(chacha20Key,
			chunkBuf)
	}
	return chunkBuf
}

// assembleHeader builds the gdz file header.
func assembleHeader(salt []byte) []byte {
	if fileVersion[0] != 0x65 {
		log.Fatal("Unknown file version specified. Aborting.")
	}
	// Build the header. The format for version 0x65 is:
	// [magic] [version] [mode] [saltLen] [salt] [scryptNlen] [scryptN] ->
	// [scryptR] [scryptP]
	//
	// The mode as uint8
	modeByte := []byte{byte(uint8(mode))}
	// Saltlength in bytes. If the salt gets larger than 255 bytes,
	// another type is needed. (This is not recommended.)
	saltLengthByte := []byte{byte(len(salt))}
	// In Golang, an int is at least 32 bits long. Better play it
	// safe and reserve 64 bits.
	scryptNSize := []byte{sixtyFourBit}
	scryptNBytes := make([]byte, sixtyFourBit)
	binary.BigEndian.PutUint64(scryptNBytes, uint64(scryptN))
	// Current sane values for r can be represented as uint8.
	// The byte indicates the uint8 value for r.
	scryptRByte := []byte{byte(uint8(scryptR))}
	// The same goes for p:
	scryptPByte := []byte{byte(uint8(scryptP))}
	header := append(magic, fileVersion...)
	header = append(header, modeByte...)
	header = append(header, saltLengthByte...)
	header = append(header, salt...)
	header = append(header, scryptNSize...)
	header = append(header, scryptNBytes...)
	header = append(header, scryptRByte...)
	header = append(header, scryptPByte...)

	return header
}

// readHeader reads and interprets the header of a gdz file
func readHeader(inFile *os.File) (int, []byte) {
	bytesRead := 0
	// Read the header:
	//
	// This is a litany of reading and interpreting the first few
	// bytes of a gdz file.
	//
	// Go to position zero in the file
	_, err := inFile.Seek(0, 0)
	check(err)
	//
	// [4]magic: get the first four bytes and interpret them.
	inMagic := make([]byte, 4)
	br, err := inFile.Read(inMagic)
	check(err)
	bytesRead += br
	if !bytes.Equal(inMagic, magic) {
		// Wrong magic number. This will not end well.
		// We have to stop here as we have no idea how to handle
		// what comes next.
		statusCode = 3 // wrong file type
		return bytesRead, []byte{}
	}
	//
	// [1]version: take the next byte. - You get the picture.
	inVersion := make([]byte, 1)
	br, err = inFile.Read(inVersion)
	check(err)
	bytesRead += br
	if !bytes.Equal(inVersion, fileVersion) {
		// Unrecognized version. We cannot continue.
		statusCode = 4 // unknown version
		return bytesRead, []byte{}
	}
	logMsg("This seems to be a gdzip encrypted file.\n")
	//
	// [1]mode
	inModeBytes := make([]byte, 1)
	br, err = inFile.Read(inModeBytes)
	check(err)
	bytesRead += br
	mode = uint8(inModeBytes[0])
	//
	// [1]saltLength
	inSaltLenBytes := make([]byte, 1)
	br, err = inFile.Read(inSaltLenBytes)
	check(err)
	bytesRead += br
	inSaltLen := uint8(inSaltLenBytes[0])
	//
	// [saltLen]salt
	salt := make([]byte, inSaltLen)
	br, err = inFile.Read(salt)
	check(err)
	bytesRead += br
	//
	// [1]scryptNLen
	inScryptNLenBytes := make([]byte, 1)
	br, err = inFile.Read(inScryptNLenBytes)
	check(err)
	bytesRead += br
	inScryptNLen := uint8(inScryptNLenBytes[0])
	//
	// [scryptNLen]scryptN
	inScryptNBytes := make([]byte, inScryptNLen)
	br, err = inFile.Read(inScryptNBytes)
	check(err)
	bytesRead += br
	scryptN = int(binary.BigEndian.Uint64(inScryptNBytes))
	//
	// [1]scryptR
	inScryptRBytes := make([]byte, 1)
	br, err = inFile.Read(inScryptRBytes)
	check(err)
	bytesRead += br
	scryptR = int(inScryptRBytes[0])
	//
	// [1]scryptP
	inScryptPBytes := make([]byte, 1)
	br, err = inFile.Read(inScryptPBytes)
	check(err)
	bytesRead += br
	scryptP = int(inScryptPBytes[0])
	//
	// We're done with reading the header.
	return bytesRead, salt
}

// logMsg is a shorthand for logging to stdout.
func logMsg(msg string) {
	if !quiet {
		fmt.Printf(msg)
	}
}

// getPassphrase gets the passphrase from the user. Will not echo.
// Currently, this uses ReadPassword() from x/crypto/ssh/terminal.
func getPassphrase(encrypt bool) []byte {
	var passphrase []byte
	match := false // whether the phrases given are the same

	if encrypt {
		for match == false {
			fmt.Printf("\nEnter a passphrase for encryption: ")
			bytePassword, err := terminal.ReadPassword(int(
				syscall.Stdin))
			check(err)

			fmt.Printf("\n\nPlease verify the passphrase: ")
			bytePassword1, err := terminal.ReadPassword(int(
				syscall.Stdin))
			check(err)

			if bytes.Equal(bytePassword, bytePassword1) {
				match = true
				passphrase = bytePassword

			} else {
				fmt.Println("\nSorry - passphrases" +
					" don't match. Please try again.")
			}
		}
	} else {
		fmt.Printf("\n\nEnter a passphrase for decryption: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		check(err)
		passphrase = bytePassword
	}

	return passphrase
}

// generateKey returns two 256bit keys. If only one key is requested depending
// on the mode, the other one is of length zero.
func generateKey(salt []byte, passphrase []byte) ([]byte, []byte) {
	var chacha20Key []byte
	var aes256Key []byte
	switch mode {
	case 1:
		aes256Key = getKey(salt, passphrase, keyLength)[:32]
		chacha20Key = []byte{0}
	case 2:
		aes256Key = []byte{0}
		chacha20Key = getKey(salt, passphrase, keyLength)[:32]
	case 3:
		longKey := getKey(salt, passphrase, keyLength*2)[:]
		aes256Key = longKey[:32]
		chacha20Key = longKey[32:]
	case 4:
		longKey := getKey(salt, passphrase, keyLength*2)[:]
		aes256Key = longKey[32:]
		chacha20Key = longKey[:32]
	}
	return chacha20Key, aes256Key
}

// getKey generates a key from the passphrase using the salt.
// getKey() relies upon golang.org/x/crypto/scrypt
func getKey(salt []byte, psw []byte, length int) []byte {
	dk, err := scrypt.Key(psw, salt, scryptN, scryptR, scryptP,
		length)
	check(err)

	return dk
}

// getRandomBytes returns a slice of cryptographically secure random bytes.
// In current versions of golang, getrandom(2) seems to have precedence as long
// as the machine's entropy pool is not exhausted and the getrandom syscall is
// available; otherwise, crypto/rand will fall back to using /dev/urandom.
// From the crypto/rand package documentation:
// On Linux, Reader uses getrandom(2) if available, /dev/urandom otherwise.
// On OpenBSD, Reader uses getentropy(2).
// On other Unix-like systems, Reader reads from /dev/urandom.
// On Windows systems, Reader uses the CryptGenRandom API.
func getRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	check(err)

	return b
}

func printAmbiguityError() {
	var msg = `
It is unclear what you want to do exactly.
Either specify a file to encrypt with "-encrypt [FILENAME]"
or a file to decrypt with "-decrypt [FILENAME]".

See gdzip -h for full help.
`
	fmt.Println(msg)
	statusCode = 3 // ambigouous input

	return
}

// check for errors and quit if an error occurred.
func check(err error) {
	if err != nil {
		fmt.Printf("\n")
		panic(err)
	}
}
