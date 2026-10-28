package coreapi

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStatusCounterDuplicateGapEpochAndRegression(t *testing.T) {
	var counter StatusCounter
	status := func(up, down int64) Status {
		return Status{TrafficAvailable: true, UplinkTotal: up, DownlinkTotal: down}
	}
	if delta, err := counter.Apply("pid-start-1", status(100, 200)); err != nil || !delta.Baseline || delta.Uplink != 0 {
		t.Fatalf("first sample %+v %v", delta, err)
	}
	if delta, err := counter.Apply("pid-start-1", status(120, 250)); err != nil || delta.Uplink != 20 || delta.Downlink != 50 {
		t.Fatalf("delta %+v %v", delta, err)
	}
	if delta, err := counter.Apply("pid-start-1", status(120, 250)); err != nil || delta.Uplink != 0 || delta.Downlink != 0 {
		t.Fatalf("duplicate %+v %v", delta, err)
	}
	// Persistence and same-core reconnect recover the global monotonic change.
	encoded, _ := json.Marshal(counter)
	var restored StatusCounter
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	counter = restored
	counter.MarkGap()
	if delta, err := counter.Apply("pid-start-1", status(180, 400)); err != nil || !delta.Gap || delta.Uplink != 60 || delta.Downlink != 150 {
		t.Fatalf("reconnect %+v %v", delta, err)
	}
	if delta, err := counter.Apply("pid-start-1", status(110, 210)); !errors.Is(err, ErrCounterRegression) || !delta.Gap || !delta.Reset {
		t.Fatalf("regression %+v %v", delta, err)
	}
	if delta, err := counter.Apply("pid-start-1", status(180, 400)); err != nil || delta.Uplink != 0 || delta.Downlink != 0 {
		t.Fatalf("replay after rollback %+v %v", delta, err)
	}
	if delta, err := counter.Apply("pid-start-2", status(15, 30)); err != nil || !delta.Baseline || !delta.Reset || !delta.Gap || delta.Uplink != 0 {
		t.Fatalf("new epoch %+v %v", delta, err)
	}
	if delta, err := counter.Apply("pid-start-2", status(20, 40)); err != nil || delta.Uplink != 5 || delta.Downlink != 10 {
		t.Fatalf("new delta %+v %v", delta, err)
	}
	if counter.ObservedUplink != 85 || counter.ObservedDownlink != 210 {
		t.Fatalf("observed %+v", counter)
	}
	if _, err := counter.Apply("pid-start-2", Status{}); !errors.Is(err, ErrUnavailable) || !counter.Interrupted {
		t.Fatalf("unavailable %v", err)
	}
	if _, err := counter.Apply("", status(1, 2)); err == nil {
		t.Fatal("accepted missing epoch")
	}
}

func TestConnectionResetsAndDuplicateDeltasNeverBecomeBilling(t *testing.T) {
	var view ConnectionView
	connection := Connection{ID: "one", Inbound: "node-tag", User: "user-tag", UplinkTotal: 100, DownlinkTotal: 200}
	initial := ConnectionBatch{Reset: true, Events: []ConnectionEvent{{ID: "one", Connection: &connection}}}
	if err := view.Apply("epoch-1", initial); err != nil {
		t.Fatal(err)
	}
	update := ConnectionBatch{Events: []ConnectionEvent{{Type: 1, ID: "one", UplinkDelta: 50, DownlinkDelta: 70}}}
	for range 2 {
		if err := view.Apply("epoch-1", update); err != nil {
			t.Fatal(err)
		}
	}
	if view.Connections["one"].UplinkTotal != 100 {
		t.Fatal("added unsequenced delta to absolute total")
	}
	view.MarkGap()
	if err := view.Apply("epoch-1", update); !errors.Is(err, ErrProtocol) {
		t.Fatal("accepted no reset after reconnect", err)
	}
	if err := view.Apply("epoch-1", ConnectionBatch{Reset: true}); err != nil || len(view.Connections) != 0 || !view.Gap {
		t.Fatalf("reset %v %+v", err, view)
	}
	if err := view.Apply("epoch-2", initial); err != nil || view.Epoch != "epoch-2" {
		t.Fatal(err)
	}
	index := Ownership{NodesByInbound: map[string]string{"node-tag": "stable-node"}, UsersByInbound: map[string]map[string]string{"node-tag": {"user-tag": "stable-user"}}}
	if node, user := index.Resolve(connection); node != "stable-node" || user != "stable-user" {
		t.Fatal(node, user)
	}
	connection.User = ""
	if _, user := index.Resolve(connection); user != UnknownOwner {
		t.Fatal("invented user", user)
	}
	connection.Inbound = "missing"
	connection.User = "user-tag"
	if node, user := index.Resolve(connection); node != UnknownOwner || user != UnknownOwner {
		t.Fatal("cross-inbound attribution", node, user)
	}
}
