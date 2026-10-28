package probe

import "sort"

func summarize(samples []Sample, kind, metric, unit string) Statistics {
	s := Statistics{Unit: unit}
	values := []float64{}
	for _, v := range samples {
		if kind != "" && v.Kind != kind {
			continue
		}
		s.Attempts++
		if v.Status != "success" {
			continue
		}
		s.Successes++
		var p *float64
		switch metric {
		case "elapsed":
			p = v.ElapsedMS
		case "ttfb":
			p = v.TTFBMS
		case "throughput":
			p = v.ThroughputMbps
		}
		if p != nil {
			values = append(values, *p)
		}
	}
	if s.Attempts > 0 {
		v := float64(s.Successes) / float64(s.Attempts)
		s.SuccessRate = &v
	}
	s.Values = len(values)
	if len(values) > 0 {
		sort.Float64s(values)
		m := values[len(values)/2]
		if len(values)%2 == 0 {
			m = (values[len(values)/2-1] + m) / 2
		}
		s.Median = &m
		p := percentile(values, .95)
		s.P95 = &p
	}
	return s
}

// Nearest-rank p95 deliberately reports an observed sample, without creating
// precision through interpolation when there are only a few measurements.
func percentile(sorted []float64, p float64) float64 {
	index := int(float64(len(sorted)) * p)
	if float64(index) < float64(len(sorted))*p {
		index++
	}
	if index < 1 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}

func statistics(samples []Sample) map[string]Statistics {
	r := map[string]Statistics{}
	for _, p := range []struct{ k, kind, metric, unit string }{{"idle_request", "idle", "elapsed", "ms"}, {"load_request", "load", "elapsed", "ms"}, {"https_ttfb", "", "ttfb", "ms"}, {"download_throughput", "download", "throughput", "Mbps"}} {
		s := summarize(samples, p.kind, p.metric, p.unit)
		if s.Attempts > 0 {
			r[p.k] = s
		}
	}
	return r
}
