package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func BenchmarkGatherWithContext(b *testing.B) {
	size := 100000 // number of metric families in response
	rand.Seed(time.Now().UnixNano())
	helpMsg := "help msg"
	labelName := "label"
	metricFamilies := make([]*dto.MetricFamily, size)
	metricType := dto.MetricType_GAUGE
	for i, _ := range metricFamilies {
		metrics := make([]*dto.Metric, 10)
		for i, _ := range metrics {
			labelValue := fmt.Sprint(rand.Int63())
			value := rand.Float64()
			ts := time.Now().UnixNano()
			metrics[i] = &dto.Metric{
				Label: []*dto.LabelPair{
					&dto.LabelPair{
						Name:  &labelName,
						Value: &labelValue,
					},
				},
				Gauge: &dto.Gauge{
					Value: &value,
				},
				TimestampMs: &ts,
			}
		}
		metricName := fmt.Sprintf("metric%d", rand.Int63())
		metricFamilies[i] = &dto.MetricFamily{
			Name:   &metricName,
			Help:   &helpMsg,
			Type:   &metricType,
			Metric: metrics,
		}
	}

	// prepare mux for server
	buf := &bytes.Buffer{}
	enc := expfmt.NewEncoder(buf, expfmt.FmtText)
	for _, mf := range metricFamilies {
		enc.Encode(mf)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		reader := bytes.NewReader(buf.Bytes())
		io.Copy(w, reader)
	})

	// run server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to bind to 127.0.0.1:0 - %v", err)
	}
	listenPort := listener.Addr().(*net.TCPAddr).Port
	server := http.Server{Handler: mux}
	go func() { server.Serve(listener) }()
	defer server.Close()

	cfg := moduleConfig{
		name:    "test",
		Method:  "http",
		Timeout: time.Minute,
		HTTP: httpConfig{
			Port: listenPort,
		},
	}

	if err := checkModuleConfig("test", &cfg); err != nil {
		b.Fatalf("Failed to check module config: %v", err)
	}

	baseRequest, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/proxy?module=test", nil)
	if err != nil {
		b.Fatalf("Failed to create base request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := *baseRequest
		gather := cfg.HTTP.GatherWithContext(context.Background(), &request)
		mfs, err := gather()
		if err != nil {
			b.Fatalf("Failed to gather metrics: %v", err)
		}
		if len(mfs) != size {
			b.Fatalf("Expected to get %d metric families but got %d", size, len(mfs))
		}
	}
}
