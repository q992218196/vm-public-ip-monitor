package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
	"vm-monitor/agent/internal/capture"
	"vm-monitor/agent/internal/config"
	"vm-monitor/agent/internal/engine"
	"vm-monitor/agent/internal/spool"
	"vm-monitor/agent/internal/wire"
)

var version = "0.3.0"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	conf := flag.String("config", "/home/vm-monitor/config/agent.json", "configuration path")
	check := flag.Bool("check", false, "validate configuration and paths without capture")
	replay := flag.String("replay", "", "replay an Ethernet classic PCAP and print batch JSON, without uploading")
	flag.Parse()
	c, e := config.Load(*conf)
	if e != nil {
		return e
	}
	debug.SetMemoryLimit(c.MemorySoftMiB * 1024 * 1024)
	if *check {
		fmt.Printf("configuration valid; %d CIDRs; data=%s; work budget=%d MiB; interfaces=%v\n", len(c.CIDRs), c.DataDir, c.MemorySoftMiB, c.Interfaces)
		return nil
	}
	if *replay != "" {
		return replayPCAP(*replay, c)
	}
	if e = os.MkdirAll(filepath.Join(c.DataDir, "logs"), 0700); e != nil {
		return e
	}
	// The logger is one bounded file; systemd stdout is disabled by the unit.
	lp := filepath.Join(c.DataDir, "logs", "agent.log")
	f, e := os.OpenFile(lp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() { f.Close() }()
	log.SetOutput(f)
	s, e := spool.New(c)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), capture.StopSignals()...)
	defer cancel()
	eng := engine.New(c, time.Now())
	errs := make(chan error, len(c.Interfaces))
	for _, iface := range c.Interfaces {
		go func(name string) {
			if e := capture.Run(ctx, name, c.CaptureBufferMiB, eng.Process, eng.KernelDrops); e != nil {
				errs <- fmt.Errorf("capture %s: %w", name, e)
			}
		}(iface)
	}
	go func() {
		backoff := time.Second
		for ctx.Err() == nil {
			ok, e := s.SendOne(ctx)
			if e != nil {
				log.Printf("upload: %v", e)
				backoff *= 2
				if backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
			} else {
				backoff = time.Second
			}
			if ok {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}()
	flush := time.NewTicker(time.Duration(c.FlushSeconds) * time.Second)
	defer flush.Stop()
	sweep := time.NewTicker(time.Second)
	defer sweep.Stop()
	var lastSpoolDropped uint64
	snapshot := func() {
		b := eng.Snapshot(time.Now())
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		b.Health.Version = version
		b.Health.HeapBytes = m.HeapAlloc
		b.Health.RSSBytes = capture.RSS()
		b.Health.Interfaces = c.Interfaces
		var totalDropped uint64
		b.Health.SpoolBytes, totalDropped = s.Status()
		b.Health.SpoolDropped = totalDropped - lastSpoolDropped
		lastSpoolDropped = totalDropped
		b.Health.DiskBytes = spool.DirBytes(c.DataDir)
		if e = s.Put(b); e != nil {
			log.Print(e)
		}
	}
	log.Printf("started %s; interfaces=%v", version, c.Interfaces)
	for {
		select {
		case <-ctx.Done():
			snapshot()
			return nil
		case e := <-errs:
			return e
		case <-flush.C:
			snapshot()
		case now := <-sweep.C:
			eng.Sweep(now)
			if i, _ := f.Stat(); i != nil && i.Size() > 8*1024*1024 {
				f.Close()
				os.Remove(lp + ".1")
				os.Rename(lp, lp+".1")
				f, e = os.OpenFile(lp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if e != nil {
					return e
				}
				log.SetOutput(f)
			}
		}
	}
}
func replayPCAP(path string, c config.Config) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := make([]byte, 24)
	if _, e = io.ReadFull(f, h); e != nil {
		return e
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(h[:4]) {
	case 0xa1b2c3d4:
		order = binary.LittleEndian
	case 0xd4c3b2a1:
		order = binary.BigEndian
	default:
		return fmt.Errorf("only microsecond classic PCAP supported")
	}
	if order.Uint32(h[20:24]) != 1 {
		return fmt.Errorf("PCAP must contain Ethernet")
	}
	var eng *engine.Engine
	var last time.Time
	for {
		r := make([]byte, 16)
		_, e = io.ReadFull(f, r)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		n := order.Uint32(r[8:12])
		if n > 65536 {
			return fmt.Errorf("PCAP record too large")
		}
		b := make([]byte, n)
		if _, e = io.ReadFull(f, b); e != nil {
			return e
		}
		last = time.Unix(int64(order.Uint32(r[:4])), int64(order.Uint32(r[4:8]))*1000)
		if eng == nil {
			eng = engine.New(c, last)
		}
		eng.Sweep(last)
		eng.Process(b, int(order.Uint32(r[12:16])), "pcap", last)
	}
	if eng == nil {
		return fmt.Errorf("empty PCAP")
	}
	b := eng.Snapshot(last.Add(time.Second))
	b.Health.Version = version
	return json.NewEncoder(os.Stdout).Encode(wire.Batch(b))
}
