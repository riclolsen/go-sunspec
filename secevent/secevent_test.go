// SPDX-License-Identifier: MIT

package secevent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/otfabric/go-modbus"
	"github.com/otfabric/go-sunspec"
	"github.com/otfabric/go-sunspec/secevent"
)

func TestEventDispatch(t *testing.T) {
	if _, err := secevent.NewDispatcher(secevent.Config{}); !errors.Is(err, secevent.ErrNoSink) {
		t.Fatalf("NewDispatcher without a sink: %v", err)
	}
	kind := secevent.KindConnAccepted
	info, ok := secevent.Describe(kind)
	if !ok || info.Category != secevent.CategoryConnection || !slices.Contains(secevent.Kinds(), kind) {
		t.Fatalf("connection event missing from catalogue: %+v, %t", info, ok)
	}

	events := make(chan secevent.Event, 1)
	var output bytes.Buffer
	sink := secevent.MultiSink(
		secevent.NewChannelSink(events),
		secevent.NewJSONLinesSink(&output),
		secevent.LoggerSink(modbus.NopLogger()),
	)
	dispatcher, err := secevent.NewDispatcher(secevent.Config{
		Sink:            secevent.FilterSink(info.Severity, sink, info.Category),
		AggregateWindow: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dispatcher.CloseNoWait)

	connID := secevent.NextConnID()
	peer := secevent.PeerInfo{Network: "tcp", RemoteAddr: netip.MustParseAddrPort("127.0.0.1:12345")}
	reporter := secevent.NewConnReporter(dispatcher, secevent.Event{ConnID: connID, Peer: peer})
	if secevent.Report(t.Context(), secevent.Event{Kind: kind}) {
		t.Fatal("Report succeeded on a context without a reporter")
	}
	ctx := secevent.NewContext(t.Context(), reporter)
	if got, ok := secevent.PeerFromContext(ctx); !ok || got != peer {
		t.Fatalf("PeerFromContext: %+v, %t", got, ok)
	}
	if !secevent.Report(ctx, secevent.Event{Kind: kind}) {
		t.Fatal("Report failed on a context with a reporter")
	}
	drainCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Close(drainCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Kind != kind || event.ConnID != connID || event.Peer != peer {
			t.Errorf("dispatched event: %+v", event)
		}
	default:
		t.Fatal("no dispatched event")
	}
	var record struct {
		Kind secevent.Kind `json:"kind"`
	}
	if err := json.Unmarshal(output.Bytes(), &record); err != nil || record.Kind != kind {
		t.Errorf("JSON event: %s, %v", output.Bytes(), err)
	}
}

func TestServerSecurityEvents(t *testing.T) {
	device, err := sunspec.NewServer(nil, sunspec.ServerModel{ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan secevent.Event, 4)
	cfg := &modbus.ServerConfig{
		URL: "tcp://127.0.0.1:0",
		Security: &secevent.SecurityPolicy{
			Policy: secevent.Policy{Sink: secevent.NewChannelSink(events)},
		},
	}
	server, err := modbus.NewServer(cfg, device)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Error(err)
		}
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := modbus.New(modbus.Config{URL: "tcp://" + server.Addr().String(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.OpenContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sunspec.Discover(ctx, client, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	var connID uint64
	var kinds []secevent.Kind
	for len(events) > 0 {
		event := <-events
		kinds = append(kinds, event.Kind)
		if event.Kind == secevent.KindConnAccepted {
			connID = event.ConnID
		}
		if event.Kind == secevent.KindConnClosed && (connID == 0 || event.ConnID != connID) {
			t.Errorf("close event connection ID = %d, want %d", event.ConnID, connID)
		}
	}
	if want := []secevent.Kind{secevent.KindConnAccepted, secevent.KindConnClosed}; !slices.Equal(kinds, want) {
		t.Errorf("event kinds = %v, want %v", kinds, want)
	}
	stats := server.SecurityStats()
	if stats.Delivered != 2 {
		t.Errorf("delivered %d events, want 2", stats.Delivered)
	}

	cfg.Security.QueueSize = -1
	if err := device.Serve(ctx, cfg); !errors.Is(err, modbus.ErrConfigurationError) {
		t.Errorf("Serve with an invalid security policy: %v", err)
	}
}
