// SPDX-License-Identifier: MIT

// Package secevent exposes the go-modbus security event API for SunSpec
// servers. Set [modbus.ServerConfig.Security] to a [SecurityPolicy] when
// calling [modbus.NewServer] or serving a SunSpec device with Server.Serve.
// Applications importing this package must select a go-modbus version that
// provides security events. See the go-sunspec README for the fork pin.
package secevent

import (
	"context"
	"io"

	"github.com/otfabric/go-modbus"
	upstream "github.com/otfabric/go-modbus/secevent"
)

// SecurityPolicy configures event delivery on a Modbus server.
type SecurityPolicy = modbus.SecurityPolicy

// Event is one security observation made by a Modbus endpoint.
type Event = upstream.Event

// Kind is the stable code for an event.
type Kind = upstream.Kind

// KindInfo describes an event kind's defaults and aggregation behavior.
type KindInfo = upstream.KindInfo

// Category groups related kinds of events.
type Category = upstream.Category

// Severity expresses the importance of an event.
type Severity = upstream.Severity

// Action describes how the endpoint responded to an observation.
type Action = upstream.Action

// FieldMask records which protocol fields are present in an event.
type FieldMask = upstream.FieldMask

// FunctionCode is the Modbus request function code.
type FunctionCode = upstream.FunctionCode

// ExceptionCode is the Modbus response exception code.
type ExceptionCode = upstream.ExceptionCode

// PeerInfo identifies a connection's peer.
type PeerInfo = upstream.PeerInfo

// TLSPeer describes a TLS peer's certificate and session parameters.
type TLSPeer = upstream.TLSPeer

// Policy selects a sink or a shared dispatcher for an endpoint.
type Policy = upstream.Policy

// Config configures an event dispatcher.
type Config = upstream.Config

// Dispatcher queues, aggregates and delivers events to a sink.
type Dispatcher = upstream.Dispatcher

// Stats holds a dispatcher's event counters.
type Stats = upstream.Stats

// Sink receives security events.
type Sink = upstream.Sink

// SinkFunc adapts an event callback to Sink.
type SinkFunc = upstream.SinkFunc

// ChannelSink delivers events to a channel.
type ChannelSink = upstream.ChannelSink

// JSONLinesSink writes one JSON object per event.
type JSONLinesSink = upstream.JSONLinesSink

// Logger is the logging interface used by LoggerSink.
type Logger = upstream.Logger

// Reporter reports events and provides peer information for a connection.
type Reporter = upstream.Reporter

// ConnReporter adds connection information to each event it reports.
type ConnReporter = upstream.ConnReporter

// The event kinds currently defined by go-modbus.
const (
	KindConnAccepted        = upstream.KindConnAccepted
	KindConnUnexpected      = upstream.KindConnUnexpected
	KindConnRejectedLimit   = upstream.KindConnRejectedLimit
	KindConnNoRequest       = upstream.KindConnNoRequest
	KindConnIdleTimeout     = upstream.KindConnIdleTimeout
	KindConnClosed          = upstream.KindConnClosed
	KindConnAcceptError     = upstream.KindConnAcceptError
	KindTLSHandshakeEvicted = upstream.KindTLSHandshakeEvicted
	KindProtoBadMBAP        = upstream.KindProtoBadMBAP
	KindProtoBadPDU         = upstream.KindProtoBadPDU
	KindDoSWriteStall       = upstream.KindDoSWriteStall
	KindMetaEventsDropped   = upstream.KindMetaEventsDropped
	KindMetaSinkPanic       = upstream.KindMetaSinkPanic
)

// The event categories.
const (
	CategoryConnection  = upstream.CategoryConnection
	CategoryPeer        = upstream.CategoryPeer
	CategoryTLS         = upstream.CategoryTLS
	CategoryProtocol    = upstream.CategoryProtocol
	CategoryAccess      = upstream.CategoryAccess
	CategoryControl     = upstream.CategoryControl
	CategoryRecon       = upstream.CategoryRecon
	CategoryUnsolicited = upstream.CategoryUnsolicited
	CategoryFlood       = upstream.CategoryFlood
	CategoryResource    = upstream.CategoryResource
	CategoryRemote      = upstream.CategoryRemote
	CategoryMeta        = upstream.CategoryMeta
)

// The event severity levels in increasing order.
const (
	SeverityInfo     = upstream.SeverityInfo
	SeverityNotice   = upstream.SeverityNotice
	SeverityWarning  = upstream.SeverityWarning
	SeverityAlert    = upstream.SeverityAlert
	SeverityCritical = upstream.SeverityCritical
)

// The actions an endpoint can report.
const (
	ActionObserved     = upstream.ActionObserved
	ActionRejected     = upstream.ActionRejected
	ActionThrottled    = upstream.ActionThrottled
	ActionDisconnected = upstream.ActionDisconnected
	ActionBlocked      = upstream.ActionBlocked
)

// The presence bits for Modbus protocol fields on an event.
const (
	FieldUnitID        = upstream.FieldUnitID
	FieldFunctionCode  = upstream.FieldFunctionCode
	FieldSubFunction   = upstream.FieldSubFunction
	FieldException     = upstream.FieldException
	FieldAddress       = upstream.FieldAddress
	FieldQuantity      = upstream.FieldQuantity
	FieldTransactionID = upstream.FieldTransactionID
	FieldExpectedTxnID = upstream.FieldExpectedTxnID
)

// The dispatcher defaults applied to zero-valued configuration fields.
const (
	DefaultQueueSize        = upstream.DefaultQueueSize
	DefaultAggregateWindow  = upstream.DefaultAggregateWindow
	DefaultMaxAggregateKeys = upstream.DefaultMaxAggregateKeys
	DefaultMaxRaw           = upstream.DefaultMaxRaw
)

// ErrNoSink is returned when a dispatcher is created without a sink.
var ErrNoSink = upstream.ErrNoSink

// Describe returns the catalogue entry for kind, if it is known.
func Describe(kind Kind) (KindInfo, bool) {
	return upstream.Describe(kind)
}

// Kinds returns the catalogue's event kinds in sorted order.
func Kinds() []Kind {
	return upstream.Kinds()
}

// NewDispatcher starts a dispatcher for cfg. The caller owns its lifecycle.
func NewDispatcher(cfg Config) (*Dispatcher, error) {
	return upstream.NewDispatcher(cfg)
}

// NewChannelSink sends events to ch and counts drops when it is full.
func NewChannelSink(ch chan<- Event) *ChannelSink {
	return upstream.NewChannelSink(ch)
}

// NewJSONLinesSink writes events to w as newline-delimited JSON.
func NewJSONLinesSink(w io.Writer) *JSONLinesSink {
	return upstream.NewJSONLinesSink(w)
}

// MultiSink sends each event to the supplied sinks in order.
func MultiSink(sinks ...Sink) Sink {
	return upstream.MultiSink(sinks...)
}

// FilterSink forwards events at or above min and within the given categories.
// With no categories, it filters by severity alone.
func FilterSink(min Severity, s Sink, categories ...Category) Sink {
	return upstream.FilterSink(min, s, categories...)
}

// LoggerSink writes events to l at a log level based on event severity.
func LoggerSink(l Logger) Sink {
	return upstream.LoggerSink(l)
}

// NextConnID allocates a connection ID from go-modbus's process-wide sequence.
func NextConnID() uint64 {
	return upstream.NextConnID()
}

// NewConnReporter reports events to d using base for connection metadata.
func NewConnReporter(d *Dispatcher, base Event) *ConnReporter {
	return upstream.NewConnReporter(d, base)
}

// NewContext associates a reporter with ctx for Report and PeerFromContext.
func NewContext(ctx context.Context, r Reporter) context.Context {
	return upstream.NewContext(ctx, r)
}

// Report sends an event through the reporter in ctx. It returns false when
// there is no reporter. Keep register values and payloads out of Detail.
func Report(ctx context.Context, e Event) bool {
	return upstream.Report(ctx, e)
}

// PeerFromContext returns the peer associated with ctx, if present.
func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	return upstream.PeerFromContext(ctx)
}
