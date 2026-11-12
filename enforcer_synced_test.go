// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/util"
)

func testEnforceSync(t *testing.T, e *SyncedEnforcer, sub string, obj interface{}, act string, res bool) {
	t.Helper()
	if myRes, _ := e.Enforce(sub, obj, act); myRes != res {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", sub, obj, act, myRes, res)
	}
}

func TestSync(t *testing.T) {
	e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	// Start reloading the policy every 200 ms.
	e.StartAutoLoadPolicy(time.Millisecond * 200)

	testEnforceSync(t, e, "alice", "data1", "read", true)
	testEnforceSync(t, e, "alice", "data1", "write", false)
	testEnforceSync(t, e, "alice", "data2", "read", false)
	testEnforceSync(t, e, "alice", "data2", "write", false)
	testEnforceSync(t, e, "bob", "data1", "read", false)
	testEnforceSync(t, e, "bob", "data1", "write", false)
	testEnforceSync(t, e, "bob", "data2", "read", false)
	testEnforceSync(t, e, "bob", "data2", "write", true)

	// Simulate a policy change
	e.ClearPolicy()
	testEnforceSync(t, e, "bob", "data2", "write", false)

	// Wait for at least one sync
	time.Sleep(time.Millisecond * 300)

	testEnforceSync(t, e, "bob", "data2", "write", true)

	// Stop the reloading policy periodically.
	e.StopAutoLoadPolicy()
}

func TestStopAutoLoadPolicy(t *testing.T) {
	e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	e.StartAutoLoadPolicy(5 * time.Millisecond)
	if !e.IsAutoLoadingRunning() {
		t.Error("auto load is not running")
	}
	e.StopAutoLoadPolicy()
	// Need a moment, to exit goroutine
	time.Sleep(10 * time.Millisecond)
	if e.IsAutoLoadingRunning() {
		t.Error("auto load is still running")
	}
}

// waitForPolicy polls the enforcer until the expected rule is visible again or
// the deadline is exceeded. It fails the test when the deadline is reached.
func waitForPolicy(t *testing.T, e *SyncedEnforcer, rule []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := e.HasPolicy(interfaceSlice(rule)...)
		if err != nil {
			t.Fatalf("HasPolicy failed: %v", err)
		}
		if ok {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("policy %v was not reloaded within %v; auto-load is silently dead", rule, timeout)
}

func interfaceSlice(rule []string) []interface{} {
	res := make([]interface{}, len(rule))
	for i, v := range rule {
		res[i] = v
	}
	return res
}

// TestAutoLoadPolicyRestartReload reproduces the original defect: after a
// graceful restart (Stop followed immediately by Start) the auto-load goroutine
// must keep reloading policies instead of being killed by a stale stop signal.
func TestAutoLoadPolicyRestartReload(t *testing.T) {
	e, err := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewSyncedEnforcer failed: %v", err)
	}

	e.StartAutoLoadPolicy(5 * time.Millisecond)
	e.StopAutoLoadPolicy()
	// Restart without waiting for any scheduling gap: Stop is synchronous now,
	// so the old goroutine is guaranteed to be gone before the new one starts.
	e.StartAutoLoadPolicy(5 * time.Millisecond)
	if !e.IsAutoLoadingRunning() {
		t.Fatal("auto load is not running after restart")
	}

	e.ClearPolicy()
	if ok, _ := e.HasPolicy("bob", "data2", "write"); ok {
		t.Fatal("policy should have been cleared")
	}
	waitForPolicy(t, e, []string{"bob", "data2", "write"}, time.Second)

	e.StopAutoLoadPolicy()
	if e.IsAutoLoadingRunning() {
		t.Fatal("auto load is still running after stop")
	}
}

// TestAutoLoadPolicyRepeatedRestartCycles hammers start/stop back to back. With
// the buggy reusable stop channel, a leftover token would eventually make a new
// goroutine exit immediately and auto-load would never recover.
func TestAutoLoadPolicyRepeatedRestartCycles(t *testing.T) {
	e, err := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewSyncedEnforcer failed: %v", err)
	}

	const cycles = 50
	for i := 0; i < cycles; i++ {
		e.StartAutoLoadPolicy(time.Millisecond)
		// Interleave an extra Stop: double stop must be a safe no-op and must
		// never leave a stop token for the next generation.
		e.StopAutoLoadPolicy()
		e.StopAutoLoadPolicy()
		e.StartAutoLoadPolicy(time.Millisecond)
		if !e.IsAutoLoadingRunning() {
			t.Fatalf("cycle %d: auto load is not running after restart", i)
		}
		e.StopAutoLoadPolicy()
		if e.IsAutoLoadingRunning() {
			t.Fatalf("cycle %d: auto load is still running after stop", i)
		}
	}

	// Final generation must actually be functional, not just flagged as running.
	e.StartAutoLoadPolicy(5 * time.Millisecond)
	e.ClearPolicy()
	waitForPolicy(t, e, []string{"bob", "data2", "write"}, time.Second)
	e.StopAutoLoadPolicy()
}

// TestAutoLoadPolicyGoroutineLeak verifies that Stop is synchronous and every
// auto-load goroutine is actually reclaimed, instead of being left blocked on a
// reusable stop channel (the mechanism behind the silent post-restart failure).
func TestAutoLoadPolicyGoroutineLeak(t *testing.T) {
	e, err := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewSyncedEnforcer failed: %v", err)
	}

	// Settle background goroutines unrelated to the enforcer.
	runtime.GC()
	base := runtime.NumGoroutine()

	const cycles = 100
	for i := 0; i < cycles; i++ {
		e.StartAutoLoadPolicy(time.Millisecond)
		e.StopAutoLoadPolicy()
	}

	runtime.GC()
	// Give the scheduler a moment to finish reaping the final goroutine.
	time.Sleep(20 * time.Millisecond)
	if got := runtime.NumGoroutine(); got > base+1 {
		t.Fatalf("goroutine leak after %d cycles: base=%d now=%d", cycles, base, got)
	}
	if e.IsAutoLoadingRunning() {
		t.Fatal("auto load should be stopped")
	}
}

// TestStopAutoLoadPolicyIdempotent makes repeated and out-of-order Stop calls
// safe: Stop without Start and multiple Stops must neither panic nor block.
func TestStopAutoLoadPolicyIdempotent(t *testing.T) {
	e, err := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewSyncedEnforcer failed: %v", err)
	}

	// Stopping a never-started enforcer must be a no-op.
	e.StopAutoLoadPolicy()
	e.StopAutoLoadPolicy()

	e.StartAutoLoadPolicy(5 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		// Concurrent and repeated stops must not panic on closing the channel.
		e.StopAutoLoadPolicy()
		e.StopAutoLoadPolicy()
		e.StopAutoLoadPolicy()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StopAutoLoadPolicy blocked on repeated calls")
	}
	if e.IsAutoLoadingRunning() {
		t.Fatal("auto load is still running after stop")
	}
}

// TestStartAutoLoadPolicyConcurrentWithStop exercises the start/stop
// coordination under contention. Whatever the interleaving is, the enforcer
// must end in a consistent state with at most one live auto-load goroutine.
func TestStartAutoLoadPolicyConcurrentWithStop(t *testing.T) {
	e, err := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewSyncedEnforcer failed: %v", err)
	}

	const rounds = 25
	for i := 0; i < rounds; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			e.StartAutoLoadPolicy(time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			e.StopAutoLoadPolicy()
		}()
		wg.Wait()

		// Regardless of who won the race, restarting must always succeed and
		// auto-load must actually keep working afterwards.
		e.StopAutoLoadPolicy()
		e.StartAutoLoadPolicy(5 * time.Millisecond)
		if !e.IsAutoLoadingRunning() {
			t.Fatalf("round %d: auto load could not be restarted", i)
		}
		e.StopAutoLoadPolicy()
	}
}

func testSyncedEnforcerGetPolicy(t *testing.T, e *SyncedEnforcer, res [][]string) {
	t.Helper()
	myRes, err := e.GetPolicy()
	if err != nil {
		t.Error(err)
	}

	if !util.SortedArray2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	} else {
		t.Log("Policy: ", myRes)
	}
}

func TestSyncedEnforcerSelfAddPolicy(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user6", "data6", "read"}) }()
		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})
	}
}

func TestSyncedEnforcerSelfAddPolicies(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() {
			_, _ = e.SelfAddPolicies("p", "p", [][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPolicies("p", "p", [][]string{{"user3", "data3", "read"}, {"user4", "data4", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPolicies("p", "p", [][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}})
		}()

		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})
	}
}

func TestSyncedEnforcerSelfAddPoliciesEx(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() {
			_, _ = e.SelfAddPoliciesEx("p", "p", [][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPoliciesEx("p", "p", [][]string{{"user2", "data2", "read"}, {"user3", "data3", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPoliciesEx("p", "p", [][]string{{"user3", "data3", "read"}, {"user4", "data4", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPoliciesEx("p", "p", [][]string{{"user4", "data4", "read"}, {"user5", "data5", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPoliciesEx("p", "p", [][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}})
		}()
		go func() {
			_, _ = e.SelfAddPoliciesEx("p", "p", [][]string{{"user6", "data6", "read"}, {"user1", "data1", "read"}})
		}()

		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})
	}
}

func TestSyncedEnforcerSelfRemovePolicy(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user6", "data6", "read"}) }()

		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})

		go func() { _, _ = e.SelfRemovePolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfRemovePolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfRemovePolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfRemovePolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfRemovePolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfRemovePolicy("p", "p", []string{"user6", "data6", "read"}) }()

		time.Sleep(100 * time.Millisecond)
		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
		})
	}
}

func TestSyncedEnforcerSelfRemovePolicies(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user6", "data6", "read"}) }()

		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})

		go func() {
			_, _ = e.SelfRemovePolicies("p", "p", [][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}})
		}()
		go func() {
			_, _ = e.SelfRemovePolicies("p", "p", [][]string{{"user3", "data3", "read"}, {"user4", "data4", "read"}})
		}()
		go func() {
			_, _ = e.SelfRemovePolicies("p", "p", [][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}})
		}()

		time.Sleep(100 * time.Millisecond)
		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
		})
	}
}

func TestSyncedEnforcerSelfRemoveFilteredPolicy(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user6", "data6", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user7", "data7", "write"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user8", "data8", "write"}) }()
		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
			{"user7", "data7", "write"},
			{"user8", "data8", "write"},
		})

		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 0, "user1") }()
		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 0, "user2") }()
		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 1, "data3") }()
		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 1, "data4") }()
		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 0, "user5") }()
		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 0, "user6") }()
		go func() { _, _ = e.SelfRemoveFilteredPolicy("p", "p", 2, "write") }()

		time.Sleep(100 * time.Millisecond)
		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
		})
	}
}

func TestSyncedEnforcerSelfUpdatePolicy(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user6", "data6", "read"}) }()
		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})

		go func() {
			_, _ = e.SelfUpdatePolicy("p", "p", []string{"user1", "data1", "read"}, []string{"user1", "data1", "write"})
		}()
		go func() {
			_, _ = e.SelfUpdatePolicy("p", "p", []string{"user2", "data2", "read"}, []string{"user2", "data2", "write"})
		}()
		go func() {
			_, _ = e.SelfUpdatePolicy("p", "p", []string{"user3", "data3", "read"}, []string{"user3", "data3", "write"})
		}()
		go func() {
			_, _ = e.SelfUpdatePolicy("p", "p", []string{"user4", "data4", "read"}, []string{"user4", "data4", "write"})
		}()
		go func() {
			_, _ = e.SelfUpdatePolicy("p", "p", []string{"user5", "data5", "read"}, []string{"user5", "data5", "write"})
		}()
		go func() {
			_, _ = e.SelfUpdatePolicy("p", "p", []string{"user6", "data6", "read"}, []string{"user6", "data6", "write"})
		}()

		time.Sleep(100 * time.Millisecond)
		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "write"},
			{"user2", "data2", "write"},
			{"user3", "data3", "write"},
			{"user4", "data4", "write"},
			{"user5", "data5", "write"},
			{"user6", "data6", "write"},
		})
	}
}

func TestSyncedEnforcerSelfUpdatePolicies(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user1", "data1", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user2", "data2", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user3", "data3", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user4", "data4", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user5", "data5", "read"}) }()
		go func() { _, _ = e.SelfAddPolicy("p", "p", []string{"user6", "data6", "read"}) }()
		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})

		go func() {
			_, _ = e.SelfUpdatePolicies("p", "p",
				[][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}},
				[][]string{{"user1", "data1", "write"}, {"user2", "data2", "write"}})
		}()

		go func() {
			_, _ = e.SelfUpdatePolicies("p", "p",
				[][]string{{"user3", "data3", "read"}, {"user4", "data4", "read"}},
				[][]string{{"user3", "data3", "write"}, {"user4", "data4", "write"}})
		}()

		go func() {
			_, _ = e.SelfUpdatePolicies("p", "p",
				[][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}},
				[][]string{{"user5", "data5", "write"}, {"user6", "data6", "write"}})
		}()

		time.Sleep(100 * time.Millisecond)
		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "write"},
			{"user2", "data2", "write"},
			{"user3", "data3", "write"},
			{"user4", "data4", "write"},
			{"user5", "data5", "write"},
			{"user6", "data6", "write"},
		})
	}
}

func TestSyncedEnforcerAddPoliciesEx(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user2", "data2", "read"}, {"user3", "data3", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user4", "data4", "read"}, {"user5", "data5", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user2", "data2", "read"}, {"user3", "data3", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user4", "data4", "read"}, {"user5", "data5", "read"}}) }()
		go func() { _, _ = e.AddPoliciesEx([][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}}) }()
		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})
	}
}

func TestSyncedEnforcerAddNamedPoliciesEx(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user2", "data2", "read"}, {"user3", "data3", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user4", "data4", "read"}, {"user5", "data5", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user1", "data1", "read"}, {"user2", "data2", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user2", "data2", "read"}, {"user3", "data3", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user4", "data4", "read"}, {"user5", "data5", "read"}})
		}()
		go func() {
			_, _ = e.AddNamedPoliciesEx("p", [][]string{{"user5", "data5", "read"}, {"user6", "data6", "read"}})
		}()
		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetPolicy(t, e, [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"user1", "data1", "read"},
			{"user2", "data2", "read"},
			{"user3", "data3", "read"},
			{"user4", "data4", "read"},
			{"user5", "data5", "read"},
			{"user6", "data6", "read"},
		})
	}
}

func testSyncedEnforcerGetUsers(t *testing.T, e *SyncedEnforcer, res []string, name string, domain ...string) {
	t.Helper()
	myRes, err := e.GetUsersForRole(name, domain...)
	myResCopy := make([]string, len(myRes))
	copy(myResCopy, myRes)
	sort.Strings(myRes)
	sort.Strings(res)
	switch err {
	case nil:
		break
	case errors.ErrNameNotFound:
		t.Log("No name found")
	default:
		t.Error("Users for ", name, " could not be fetched: ", err.Error())
	}
	t.Log("Users for ", name, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Users for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func TestSyncedEnforcerAddGroupingPoliciesEx(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
		e.ClearPolicy()

		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user1", "member"}, {"user2", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user2", "member"}, {"user3", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user4", "member"}, {"user5", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user5", "member"}, {"user6", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user1", "member"}, {"user2", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user2", "member"}, {"user3", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user4", "member"}, {"user5", "member"}}) }()
		go func() { _, _ = e.AddGroupingPoliciesEx([][]string{{"user5", "member"}, {"user6", "member"}}) }()

		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetUsers(t, e, []string{"user1", "user2", "user3", "user4", "user5", "user6"}, "member")
	}
}

func TestSyncedEnforcerAddNamedGroupingPoliciesEx(t *testing.T) {
	for i := 0; i < 10; i++ {
		e, _ := NewSyncedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
		e.ClearPolicy()

		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user1", "member"}, {"user2", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user2", "member"}, {"user3", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user4", "member"}, {"user5", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user5", "member"}, {"user6", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user1", "member"}, {"user2", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user2", "member"}, {"user3", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user4", "member"}, {"user5", "member"}}) }()
		go func() { _, _ = e.AddNamedGroupingPoliciesEx("g", [][]string{{"user5", "member"}, {"user6", "member"}}) }()

		time.Sleep(100 * time.Millisecond)

		testSyncedEnforcerGetUsers(t, e, []string{"user1", "user2", "user3", "user4", "user5", "user6"}, "member")
	}
}
