package node

import "testing"

func TestTopologyLookupsPreferStableIDOverEarlierDisplayName(t *testing.T) {
	const earlier, wanted = "1111111111111111", "2222222222222222"
	t.Run("egress", func(t *testing.T) {
		st := NewState()
		st.Egresses = []Egress{{ID: earlier, Name: wanted}, {ID: wanted, Name: "named-egress"}}
		got, err := st.FindEgress(wanted)
		if err != nil || got != &st.Egresses[1] {
			t.Fatal("earlier egress name captured stable ID lookup", err)
		}
		got.Name = "edited-egress"
		if st.Egresses[1].Name != "edited-egress" || st.Egresses[0].Name != wanted {
			t.Fatal("lookup returned a copy or edited the wrong egress")
		}
		if got, err = st.FindEgress("edited-egress"); err != nil || got != &st.Egresses[1] {
			t.Fatal("egress name fallback was lost", err)
		}
		if _, err = st.FindEgress("missing"); err == nil {
			t.Fatal("unknown egress lookup succeeded")
		}
	})
	t.Run("policy", func(t *testing.T) {
		st := NewState()
		st.EgressPolicies = []EgressPolicy{{ID: earlier, Name: wanted}, {ID: wanted, Name: "named-policy"}}
		got, err := st.FindEgressPolicy(wanted)
		if err != nil || got != &st.EgressPolicies[1] {
			t.Fatal("earlier policy name captured stable ID lookup", err)
		}
		got.Name = "edited-policy"
		if st.EgressPolicies[1].Name != "edited-policy" || st.EgressPolicies[0].Name != wanted {
			t.Fatal("lookup returned a copy or edited the wrong policy")
		}
		if got, err = st.FindEgressPolicy("edited-policy"); err != nil || got != &st.EgressPolicies[1] {
			t.Fatal("policy name fallback was lost", err)
		}
		if _, err = st.FindEgressPolicy("missing"); err == nil {
			t.Fatal("unknown policy lookup succeeded")
		}
	})
	t.Run("forward", func(t *testing.T) {
		st := NewState()
		st.Forwards = []PortForward{{ID: earlier, Name: wanted}, {ID: wanted, Name: "named-forward"}}
		got, err := st.FindForward(wanted)
		if err != nil || got != &st.Forwards[1] {
			t.Fatal("earlier forward name captured stable ID lookup", err)
		}
		got.Name = "edited-forward"
		if st.Forwards[1].Name != "edited-forward" || st.Forwards[0].Name != wanted {
			t.Fatal("lookup returned a copy or edited the wrong forward")
		}
		if got, err = st.FindForward("edited-forward"); err != nil || got != &st.Forwards[1] {
			t.Fatal("forward name fallback was lost", err)
		}
		if _, err = st.FindForward("missing"); err == nil {
			t.Fatal("unknown forward lookup succeeded")
		}
	})
}
