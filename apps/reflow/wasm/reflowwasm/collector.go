package reflowwasm

// Append records one encoded payload unless the user-supplied output limit has
// already been reached.
func (c *outputCollector) Append(payload timedPayload) {
	if c.limit > 0 && len(c.payloads) >= c.limit {
		c.truncated = true
		return
	}
	c.payloads = append(c.payloads, payload)
}

// Done reports whether no further payloads should be produced for this run.
func (c *outputCollector) Done() bool {
	return c.limit > 0 && len(c.payloads) >= c.limit
}

// Stats converts the collector's internal limit bookkeeping into the JSON
// response shape consumed by the UI.
func (c outputCollector) Stats(inputs int) RunStats {
	return RunStats{
		Inputs:    inputs,
		Outputs:   len(c.payloads),
		Limit:     c.limit,
		Truncated: c.truncated || c.Done(),
	}
}
