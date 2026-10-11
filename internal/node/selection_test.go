package node

import "testing"

func TestSelectionPrefersExactIDsOverOtherNames(t *testing.T) {
	r, err := NewReality("example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	s := NewState()
	s.Nodes = []Node{
		{ID: "1111111111111111", Name: "2222222222222222", Protocol: "reality", Host: "127.0.0.1", Listen: "::", Port: 23456, Users: []User{NewUser("phone", "reality")}, Reality: r},
		{ID: "2222222222222222", Name: "second", Protocol: "reality", Host: "127.0.0.1", Listen: "::", Port: 23457, Users: []User{NewUser("phone", "reality")}, Reality: r},
	}
	if err := s.Validate(); err != nil {
		t.Fatal("collision state must remain valid:", err)
	}
	for _, selector := range []string{s.Nodes[1].ID, s.Nodes[1].Name} {
		got, err := s.Find(selector)
		if err != nil || got != &s.Nodes[1] {
			t.Fatalf("selector %q selected wrong node: %v, %v", selector, got, err)
		}
	}
	if _, err := s.Find("missing"); err == nil {
		t.Fatal("missing node accepted")
	}
	n := s.Nodes[0]
	n.Users = append(n.Users, NewUser("laptop", "reality"))
	n.Users[0].Name = n.Users[1].ID
	s.Nodes = []Node{n}
	if err := s.Validate(); err != nil {
		t.Fatal("credential collision state must remain valid:", err)
	}
	for _, selector := range []string{n.Users[1].ID, n.Users[1].Name} {
		got, err := SelectUser(n, selector)
		if err != nil || got.ID != n.Users[1].ID {
			t.Fatalf("selector %q selected wrong credential: %v, %v", selector, got, err)
		}
	}
	for _, selector := range []string{"", "missing"} {
		if _, err := SelectUser(n, selector); err == nil {
			t.Fatalf("ambiguous or missing credential accepted: %q", selector)
		}
	}
	if got, err := SelectUser(s.Nodes[0], n.Users[0].ID); err != nil || got.ID != n.Users[0].ID {
		t.Fatal("first exact credential no longer selectable", err)
	}
}
