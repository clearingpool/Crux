package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	colres  = "\033[0m"
	colred  = "\033[31m"
	colgrn  = "\033[32m"
	colyel  = "\033[33m"
	colcyan = "\033[36m"
	crux    = "\033[36m[\033[0mCRUX\033[36m]\033[0m"
	crit    = "\033[31m[\033[0mCRIT\033[31m]\033[0m"
	alert   = "\033[31m[\033[0mALERT\033[31m]\033[0m"
)

type Config struct {
	BlockedHashes []string `json:"blocked_hashes"`
}

func getFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func main() {
	fmt.Println("Crux EDR init...")

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("%s Memlock error: %v\n", crit, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Printf("%s EBPF loading error: %v\n", crit, err)
	}
	defer objs.Close()

	myPid := uint32(os.Getpid())
	var mapKey uint32 = 0
	if err := objs.MyPidMap.Put(mapKey, myPid); err != nil {
		fmt.Printf("%s Self-defense error: %v\n", crit, err)
	}
	fmt.Println("Self-Defense module is active. Agent PID protected by core")

	jsonFile, err := os.Open("rules.json")
	if err != nil {
		fmt.Printf("%s Rules.json loading error: %v\n", crit, err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)
	var config Config
	json.Unmarshal(byteValue, &config)

	fmt.Println("Malicous hashes base was loaded")

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		fmt.Printf("%s Error: %v\n", crit, err)
	}
	defer l.Close()

	fmt.Printf("Crux EDR was started\n\n")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Printf("%s Ringbuf reader error: %v", crit, err)
	}
	defer rd.Close()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopChan
		fmt.Println("\n[*] Crux EDR stopped...\n")
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var event bpfEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		rawPath := ""
		for _, b := range event.Filename {
			if b == 0 {
				break
			}
			rawPath += string(byte(b))
		}

		if rawPath == "" || rawPath == "crux" || rawPath == "go" {
			continue
		}

		var absPath string
		if !bytes.Contains([]byte(rawPath), []byte("/")) {
			p, err := exec.LookPath(rawPath)
			if err != nil {
				continue
			}
			absPath = p
		} else {
			p, err := filepath.Abs(rawPath)
			if err != nil {
				absPath = rawPath
			} else {
				absPath = p
			}
		}

		fileHash, err := getFileSHA256(absPath)
		if err != nil {
			continue
		}

		timeStr := time.Now().Format("15:04:05")
		comm := filepath.Base(absPath)

		isMalware := false
		for _, h := range config.BlockedHashes {
			if h == fileHash {
				isMalware = true
				break
			}
		}

		if isMalware {
			syscall.Kill(int(event.Pid), syscall.SIGKILL)

			fmt.Printf("%s %sCrux EDR warning!%s Malicious process was killed at %s\n", alert, colred, colres, timeStr)
			fmt.Printf("  Process: %s%v%s; PID: %s%v%s\n", colgrn, comm, colres, colgrn, event.Pid, colres)
			fmt.Printf("  SHA-256 hash: %s%s%s\n", colcyan, fileHash, colres)
			if event.Ppid > 1 {
				syscall.Kill(int(event.Ppid), syscall.SIGKILL)
				fmt.Printf("  EDR killed PPID: %s%v%s\n\n", colgrn, event.Ppid, colres)
			}
		}
	}
}
