package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
)

type chunkJob struct {
	index int
	data  []byte
}

type chunkResult struct {
	index int
	hash  [32]byte
	err   error
}

type proofStep struct {
	Sibling [32]byte
	IsLeft  bool // true if sibling is left of current node
}

func hashChunks(path string, chunkSize int, workers int) ([][32]byte, error) {
	if chunkSize <= 0 {
		return nil, errors.New("chunk size must be > 0")
	}
	if workers <= 0 {
		return nil, errors.New("workers must be > 0")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	jobs := make(chan chunkJob, workers*2)
	results := make(chan chunkResult, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				h := sha256.Sum256(j.data)
				results <- chunkResult{index: j.index, hash: h}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	readErrCh := make(chan error, 1)
	go func() {
		defer close(jobs)
		idx := 0
		for {
			buf := make([]byte, chunkSize)
			n, err := f.Read(buf)
			if n > 0 {
				jobs <- chunkJob{index: idx, data: buf[:n]}
				idx++
			}
			if err == io.EOF {
				readErrCh <- nil
				return
			}
			if err != nil {
				readErrCh <- err
				return
			}
		}
	}()

	leafMap := map[int][32]byte{}
	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		leafMap[r.index] = r.hash
	}

	if err := <-readErrCh; err != nil {
		return nil, err
	}

	if len(leafMap) == 0 {
		empty := sha256.Sum256(nil)
		return [][32]byte{empty}, nil
	}

	keys := make([]int, 0, len(leafMap))
	for k := range leafMap {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	leaves := make([][32]byte, 0, len(keys))
	for _, k := range keys {
		leaves = append(leaves, leafMap[k])
	}
	return leaves, nil
}

func parentHash(left, right [32]byte) [32]byte {
	var combined [64]byte
	copy(combined[:32], left[:])
	copy(combined[32:], right[:])
	return sha256.Sum256(combined[:])
}

func buildLevels(leaves [][32]byte) [][][32]byte {
	levels := make([][][32]byte, 0, 16)
	cur := make([][32]byte, len(leaves))
	copy(cur, leaves)
	levels = append(levels, cur)

	for len(cur) > 1 {
		nextLen := (len(cur) + 1) / 2
		next := make([][32]byte, 0, nextLen)
		for i := 0; i < len(cur); i += 2 {
			left := cur[i]
			right := left
			if i+1 < len(cur) {
				right = cur[i+1]
			}
			next = append(next, parentHash(left, right))
		}
		levels = append(levels, next)
		cur = next
	}
	return levels
}

func merkleRoot(leaves [][32]byte) [32]byte {
	levels := buildLevels(leaves)
	return levels[len(levels)-1][0]
}

func makeProof(levels [][][32]byte, leafIndex int) ([]proofStep, error) {
	if leafIndex < 0 || leafIndex >= len(levels[0]) {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, len(levels[0]))
	}
	proof := make([]proofStep, 0, len(levels)-1)
	idx := leafIndex

	for level := 0; level < len(levels)-1; level++ {
		nodes := levels[level]
		sib := idx ^ 1
		if sib >= len(nodes) {
			sib = idx
		}
		step := proofStep{
			Sibling: nodes[sib],
			IsLeft:  sib < idx,
		}
		proof = append(proof, step)
		idx /= 2
	}
	return proof, nil
}

func verifyProof(leaf [32]byte, proof []proofStep, root [32]byte) bool {
	cur := leaf
	for _, p := range proof {
		if p.IsLeft {
			cur = parentHash(p.Sibling, cur)
		} else {
			cur = parentHash(cur, p.Sibling)
		}
	}
	return cur == root
}

func main() {
	filePath := flag.String("file", "README.md", "File to fingerprint")
	chunkSize := flag.Int("chunk", 64*1024, "Chunk size in bytes")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of hashing workers")
	prove := flag.Int("prove", -1, "Leaf index to generate and verify proof for")
	verbose := flag.Bool("v", false, "Print all leaf hashes")
	flag.Parse()

	leaves, err := hashChunks(*filePath, *chunkSize, *workers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	levels := buildLevels(leaves)
	root := levels[len(levels)-1][0]

	fmt.Println("MerkleForge")
	fmt.Printf("file      : %s\n", *filePath)
	fmt.Printf("chunks    : %d\n", len(leaves))
	fmt.Printf("chunkSize : %d\n", *chunkSize)
	fmt.Printf("workers   : %d\n", *workers)
	fmt.Printf("levels    : %d\n", len(levels))
	fmt.Printf("root      : %s\n", hex.EncodeToString(root[:]))

	if *verbose {
		fmt.Println("\nLeaf hashes:")
		for i, h := range leaves {
			fmt.Printf("  [%d] %s\n", i, hex.EncodeToString(h[:]))
		}
	}

	if *prove >= 0 {
		proof, err := makeProof(levels, *prove)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proof error: %v\n", err)
			os.Exit(2)
		}
		ok := verifyProof(leaves[*prove], proof, root)
		fmt.Printf("\nProof for leaf %d (%d steps):\n", *prove, len(proof))
		for i, s := range proof {
			side := "right"
			if s.IsLeft {
				side = "left"
			}
			fmt.Printf("  step %d sibling(%s): %s\n", i, side, hex.EncodeToString(s.Sibling[:]))
		}
		fmt.Printf("verified  : %v\n", ok)
	}

	_ = merkleRoot // keeps function reachable for readers/tools
}
