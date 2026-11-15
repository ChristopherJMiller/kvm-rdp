//! §10.2's matchers: received frames to kvm-sim's sends by FrameId, and
//! client key presses to the HID reports kvm-sim read.
use std::collections::HashMap;
use std::time::Instant;

/// End-to-end latencies in ms: each received `(frame_id, arrival)` minus
/// the latest send of that id at or before the arrival (a looped source
/// sends each id once per loop); and how many arrivals matched no send.
/// A send's stamp bounds it from below (kvm-sim stamps a tag's write as it
/// starts), so an arrival is never its own send's before it; one nearer the
/// next send of its id than that latest one counts as unmatched — never as
/// a latency of most of a loop (PE12 review I1).
#[must_use]
pub fn latencies(sent: &[(u64, Instant)], received: &[(u64, Instant)]) -> (Vec<f64>, usize) {
    let mut by_id: HashMap<u64, Vec<Instant>> = HashMap::new();
    for (id, at) in sent {
        by_id.entry(*id).or_default().push(*at);
    }
    for v in by_id.values_mut() {
        v.sort();
    }
    let (mut out, mut unmatched) = (Vec::with_capacity(received.len()), 0);
    for (id, at) in received {
        let tx = by_id.get(id).and_then(|v| {
            let i = v.partition_point(|t| t <= at);
            let tx = v.get(i.checked_sub(1)?)?;
            match v.get(i) {
                Some(next) if next.duration_since(*at) < at.duration_since(*tx) => None,
                _ => Some(tx),
            }
        });
        match tx {
            Some(tx) => out.push(at.duration_since(*tx).as_secs_f64() * 1000.0),
            None => unmatched += 1,
        }
    }
    (out, unmatched)
}

/// §10.2's load check: FrameIds unique within one loop, the loop at least
/// `min_secs` long at `fps`.
pub fn unique_loop(ids: &[u64], fps: u32, min_secs: f64) -> Result<(), String> {
    let secs = ids.len() as f64 / f64::from(fps);
    if secs < min_secs {
        return Err(format!("the loop is {secs:.2} s, under {min_secs} s"));
    }
    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    match ids.iter().position(|id| !seen.insert(*id)) {
        Some(i) => Err(format!("frame {i}'s FrameId repeats within the loop")),
        None => Ok(()),
    }
}

/// Input latencies in ms (§10.1): each press `(usage, stamped)` — stamped
/// before its write, so the stamp bounds it from below — against the first
/// keyboard report (§3.3: `AA AA 08 …`, first key slot at byte 7) carrying
/// that usage, from the press's stamp up to the next press of that usage's
/// (so one missed press is one miss, never every later press a cycle late:
/// PE12 review I1), each report used once, in order; and how many presses
/// met none.
#[must_use]
pub fn input_latencies(
    presses: &[(u8, Instant)],
    reports: &[(Instant, Vec<u8>)],
) -> (Vec<f64>, usize) {
    let (mut out, mut missed, mut cursor) = (Vec::new(), 0, 0);
    for (k, (usage, sent)) in presses.iter().enumerate() {
        let until = presses[k + 1..]
            .iter()
            .find(|(u, _)| u == usage)
            .map(|(_, t)| *t);
        let hit = reports[cursor..].iter().position(|(at, b)| {
            at >= sent
                && until.is_none_or(|u| *at <= u)
                && b.len() >= 8
                && b[2] == 0x08
                && b[7] == *usage
        });
        match hit {
            Some(i) => {
                out.push(reports[cursor + i].0.duration_since(*sent).as_secs_f64() * 1000.0);
                cursor += i + 1;
            }
            None => missed += 1,
        }
    }
    (out, missed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn a_frame_matches_the_latest_send_of_its_id_before_it_arrived() {
        let t = Instant::now();
        let ms = |n: u64| t + Duration::from_millis(n);
        // A two-frame loop sent twice; the client got the second loop's.
        let sent = [(1, ms(0)), (2, ms(33)), (1, ms(66)), (2, ms(99))];
        let received = [(1, ms(70)), (2, ms(104)), (9, ms(110))];
        let (lat, unmatched) = latencies(&sent, &received);
        assert_eq!(lat, [4.0, 5.0]);
        assert_eq!(unmatched, 1);
    }

    #[test]
    fn a_loop_needs_unique_ids_and_ten_seconds() {
        let ids: Vec<u64> = (0..300).collect();
        assert!(unique_loop(&ids, 30, 10.0).is_ok());
        assert!(unique_loop(&ids[..299], 30, 10.0).is_err(), "9.97 s");
        let mut dup = ids.clone();
        dup[150] = 3;
        assert!(unique_loop(&dup, 30, 10.0).is_err());
    }

    #[test]
    fn each_press_meets_the_first_report_of_its_key_after_it() {
        let t = Instant::now();
        let ms = |n: u64| t + Duration::from_millis(n);
        let kbd = |usage: u8| vec![0xAA, 0xAA, 0x08, 0, 0, 0, 0, usage, 0, 0, 0, 0];
        let zero = kbd(0);
        let presses = [(0x04, ms(10)), (0x05, ms(60)), (0x06, ms(110))];
        let reports = vec![
            (ms(5), kbd(0x04)), // before its press: not it
            (ms(12), kbd(0x04)),
            (ms(13), zero.clone()),
            (ms(63), kbd(0x05)),
            (ms(64), zero),
        ];
        let (lat, missed) = input_latencies(&presses, &reports);
        assert_eq!(lat, [2.0, 3.0]);
        assert_eq!(missed, 1);
    }

    /// PE12 review I1: a loop-2 arrival 30 µs before its own send's stamp
    /// — a stamp taken once the write returned allows it — is never
    /// matched to loop 1's send of that id, 20 s earlier: a 20 s latency in
    /// the sample, and not "unmatched". With the stamp taken before the
    /// write (kvm-sim's `sim_tx` since), the same frame meets its own send.
    #[test]
    fn a_loop_two_arrival_is_never_matched_to_loop_one() {
        let t = Instant::now();
        let us = |n: u64| t + Duration::from_micros(n);
        let received = [(1, us(20_000_000))];
        // Stamped when the loop-2 write returned, 30 µs after the arrival.
        let (lat, unmatched) = latencies(&[(1, us(0)), (1, us(20_000_030))], &received);
        assert_eq!((lat, unmatched), (vec![], 1));
        // Stamped when it started, before the frame could arrive.
        let (lat, unmatched) = latencies(&[(1, us(0)), (1, us(19_999_970))], &received);
        assert_eq!(unmatched, 0);
        assert!(lat.len() == 1 && (lat[0] - 0.03).abs() < 1e-9, "{lat:?}");
    }

    /// PE12 review I1: a press whose report never came is one miss. The
    /// search stops at the next press of the same key, so the miss never
    /// takes that press's report and pushes every later press a cycle late.
    #[test]
    fn a_missed_press_never_takes_the_next_press_of_its_key() {
        let t = Instant::now();
        let ms = |n: u64| t + Duration::from_millis(n);
        let kbd = |usage: u8| vec![0xAA, 0xAA, 0x08, 0, 0, 0, 0, usage, 0, 0, 0, 0];
        // Two cycles of a, b; the first a's report is lost.
        let presses = [
            (0x04, ms(10)),
            (0x05, ms(20)),
            (0x04, ms(30)),
            (0x05, ms(40)),
        ];
        let reports = vec![
            (ms(22), kbd(0x05)),
            (ms(32), kbd(0x04)),
            (ms(42), kbd(0x05)),
        ];
        let (lat, missed) = input_latencies(&presses, &reports);
        assert_eq!((lat, missed), (vec![2.0, 2.0, 2.0], 1));
    }

    /// PE12 review m5: only a keyboard report (`AA AA 08`) is a press's —
    /// a pointer report whose byte 7 (`yLo`) happens to equal the usage is
    /// not — and a report meets one press only: one at the instant of the
    /// next press of its key is the earlier press's, and the next press
    /// takes the report after it.
    #[test]
    fn a_report_is_a_keyboard_report_and_meets_one_press() {
        let t = Instant::now();
        let ms = |n: u64| t + Duration::from_millis(n);
        let kbd = |usage: u8| vec![0xAA, 0xAA, 0x08, 0, 0, 0, 0, usage, 0, 0, 0, 0];
        let pointer = vec![0xAA, 0xAA, 0x05, 0x51, 0x00, 0x00, 0x40, 0x04, 0x20];
        let (lat, missed) =
            input_latencies(&[(0x04, ms(10))], &[(ms(11), pointer), (ms(12), kbd(0x04))]);
        assert_eq!((lat, missed), (vec![2.0], 0));
        let presses = [(0x04, ms(10)), (0x04, ms(20))];
        let reports = vec![(ms(20), kbd(0x04)), (ms(25), kbd(0x04))];
        let (lat, missed) = input_latencies(&presses, &reports);
        assert_eq!((lat, missed), (vec![10.0, 5.0], 0));
    }
}
