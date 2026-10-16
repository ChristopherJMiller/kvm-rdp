//! Allocation counting (§10.1, §10.4; Plan E Task 1.4): one `GlobalAlloc`
//! over `System` that counts every allocation process-wide — what an
//! `alloc-stats` build exports on `/metrics` — and per thread, which the
//! lib's own tests read around a measured region. A `realloc` counts as an
//! allocation (it may move); a free counts nothing.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// `const`-initialised and drop-free: reading it never allocates.
    static THREAD: Cell<u64> = const { Cell::new(0) };
}

fn note(size: usize) {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(u64::try_from(size).unwrap_or(u64::MAX), Ordering::Relaxed);
    // During this thread's TLS teardown the thread count is gone: the
    // allocation is counted process-wide only.
    let _ = THREAD.try_with(|c| c.set(c.get().wrapping_add(1)));
}

// SAFETY: every method forwards its arguments to `System` unchanged, so
// `System`'s guarantees are this allocator's; counting touches only atomics
// and a thread-local `Cell`, neither of which allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's `GlobalAlloc::alloc` contract, forwarded.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: `ptr` came from this allocator, i.e. from `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as `realloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Allocations and bytes requested since the process started (0 unless
/// this allocator is installed).
#[must_use]
pub fn totals() -> (u64, u64) {
    (
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    )
}

/// Allocations on the calling thread so far: a test reads it before and
/// after the region it measures.
#[must_use]
pub fn this_thread() -> u64 {
    THREAD.try_with(Cell::get).unwrap_or(0)
}
