// Package reflowwasm adapts ReFlow's streaming pipeline to the browser.
//
// The package accepts a finite request from JavaScript, turns pasted JSON,
// bytes, and capture files into ReFlow events, then runs those events through
// the normal decoder, processor, aggregator, and encoder stages without
// starting long-lived network sources or sinks.
package reflowwasm
