use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use dashmap::DashMap;
use librqbit_core::lengths::ValidPieceIndex;
use parking_lot::RwLock;
use peer_binary_protocol::{Message, Request};

use crate::{
    Error,
    peer_connection::WriterRequest,
    torrent_state::utils::{TimedExistence, atomic_inc},
    type_aliases::{BF, PeerHandle},
};

use self::stats::{AggregatePeerStats, AggregatePeerStatsAtomic};

use super::peer::{LivePeerState, Peer, PeerRx, PeerState, PeerTx};

pub mod stats;

// Default cap on retained peer-state entries per torrent (live + idle). Bounds memory
// growth from peer discovery (DHT/trackers/PEX) when most discovered peers never connect.
pub(crate) const DEFAULT_MAX_PEER_STATES: usize = 2000;

pub(crate) struct PeerStates {
    pub session_stats: Arc<AggregatePeerStatsAtomic>,

    // This keeps track of live addresses we connected to, for PEX.
    pub live_outgoing_peers: RwLock<HashSet<PeerHandle>>,
    pub stats: AggregatePeerStatsAtomic,
    pub states: DashMap<PeerHandle, Peer>,
    // Hard cap on the number of retained entries in `states`. New peers are not admitted
    // beyond this, and the reaper evicts idle entries down to it.
    pub max_states: usize,
}

impl Drop for PeerStates {
    fn drop(&mut self) {
        for (_, p) in std::mem::take(&mut self.states).into_iter() {
            p.destroy(self);
        }
    }
}

impl PeerStates {
    pub fn stats(&self) -> AggregatePeerStats {
        self.stats.snapshot()
    }

    pub fn add_if_not_seen(&self, addr: SocketAddr) -> Option<PeerHandle> {
        use dashmap::mapref::entry::Entry;
        // Hard ceiling: refuse to grow the map past the cap. The reaper keeps idle entries
        // below this, so there is normally headroom; this only bites during bursts of
        // discovery when every retained peer is still active/queued.
        //
        // NOTE: this must be checked *before* taking the entry guard below. `states.entry()`
        // write-locks the addr's shard, and `states.len()` read-locks every shard to count —
        // calling len() while holding the guard would deadlock on that same shard. Checking
        // first is also harmless when the addr already exists: entry() returns Occupied → None,
        // the same result this early-return produces.
        if self.states.len() >= self.max_states {
            return None;
        }
        match self.states.entry(addr) {
            Entry::Occupied(_) => None,
            Entry::Vacant(vac) => {
                vac.insert(Peer::new_with_outgoing_address(addr));
                atomic_inc(&self.stats.queued);
                atomic_inc(&self.session_stats.queued);

                atomic_inc(&self.stats.seen);
                atomic_inc(&self.session_stats.seen);
                Some(addr)
            }
        }
    }

    /// Evict the longest-idle (Dead/NotNeeded) peers until the map is at or below
    /// `target_len`. Never touches Queued/Connecting/Live peers. Returns the number
    /// of peers evicted. Cheap when already under target (no allocation).
    pub fn reap_idle_peers(&self, target_len: usize) -> usize {
        let len = self.states.len();
        if len <= target_len {
            return 0;
        }
        let want = len - target_len;

        // Collect idle candidates with their idle timestamp. We iterate (releasing shard
        // locks per item) into a Vec rather than mutating during iteration.
        let mut candidates: Vec<(PeerHandle, std::time::Instant)> = self
            .states
            .iter()
            .filter_map(|e| {
                let p = e.value();
                match p.get_state() {
                    PeerState::Dead | PeerState::NotNeeded => {
                        Some((*e.key(), p.idle_since.unwrap_or_else(std::time::Instant::now)))
                    }
                    _ => None,
                }
            })
            .collect();

        if candidates.is_empty() {
            return 0;
        }

        // Oldest idle first.
        candidates.sort_unstable_by_key(|(_, since)| *since);

        let mut evicted = 0;
        for (handle, _) in candidates.into_iter().take(want) {
            if self.drop_peer(handle).is_some() {
                evicted += 1;
            }
        }
        evicted
    }
    pub fn with_peer<R>(&self, addr: PeerHandle, f: impl FnOnce(&Peer) -> R) -> Option<R> {
        self.states.get(&addr).map(|e| f(e.value()))
    }

    pub fn with_peer_mut<R>(
        &self,
        addr: PeerHandle,
        reason: &'static str,
        f: impl FnOnce(&mut Peer) -> R,
    ) -> Option<R> {
        use crate::torrent_state::utils::timeit;
        timeit(reason, || self.states.get_mut(&addr))
            .map(|e| f(TimedExistence::new(e, reason).value_mut()))
    }

    pub fn with_live<R>(&self, addr: PeerHandle, f: impl FnOnce(&LivePeerState) -> R) -> Option<R> {
        self.with_peer(addr, |peer| peer.get_live().map(f))
            .flatten()
    }

    pub fn with_live_mut<R>(
        &self,
        addr: PeerHandle,
        reason: &'static str,
        f: impl FnOnce(&mut LivePeerState) -> R,
    ) -> Option<R> {
        self.with_peer_mut(addr, reason, |peer| peer.get_live_mut().map(f))
            .flatten()
    }

    pub fn drop_peer(&self, handle: PeerHandle) -> Option<Peer> {
        let p = self.states.remove(&handle).map(|r| r.1)?;
        let s = p.get_state();
        self.stats.dec(s);
        self.session_stats.dec(s);

        Some(p)
    }

    pub fn is_peer_not_interested_and_has_full_torrent(
        &self,
        handle: PeerHandle,
        total_pieces: usize,
    ) -> bool {
        self.with_live(handle, |live| {
            !live.peer_interested && live.has_full_torrent(total_pieces)
        })
        .unwrap_or(false)
    }

    pub fn mark_peer_interested(&self, handle: PeerHandle, is_interested: bool) -> Option<bool> {
        self.with_live_mut(handle, "mark_peer_interested", |live| {
            let prev = live.peer_interested;
            live.peer_interested = is_interested;
            prev
        })
    }

    pub fn update_bitfield(&self, handle: PeerHandle, bitfield: BF) -> Option<()> {
        self.with_live_mut(handle, "update_bitfield", |live| {
            live.bitfield = bitfield;
        })
    }

    pub fn mark_peer_connecting(&self, h: PeerHandle) -> crate::Result<(PeerRx, PeerTx)> {
        let rx = self
            .with_peer_mut(h, "mark_peer_connecting", |peer| {
                peer.idle_to_connecting(self)
                    .ok_or(Error::BugInvalidPeerState)
            })
            .ok_or(Error::BugPeerNotFound)??;
        Ok(rx)
    }

    pub fn reset_peer_backoff(&self, handle: PeerHandle) {
        self.with_peer_mut(handle, "reset_peer_backoff", |p| {
            p.stats.reset_backoff();
        });
    }

    pub fn mark_peer_not_needed(&self, handle: PeerHandle) -> Option<PeerState> {
        let prev = self.with_peer_mut(handle, "mark_peer_not_needed", |peer| {
            peer.set_not_needed(self)
        })?;
        Some(prev)
    }

    pub(crate) fn on_steal(
        &self,
        from_peer: SocketAddr,
        to_peer: SocketAddr,
        stolen_idx: ValidPieceIndex,
    ) {
        self.with_peer(to_peer, |p| {
            atomic_inc(&p.stats.counters.times_i_stole);
        });
        self.with_peer(from_peer, |p| {
            atomic_inc(&p.stats.counters.times_stolen_from_me);
        });
        self.stats.inc_steals();
        self.session_stats.inc_steals();

        self.with_live_mut(from_peer, "send_cancellations", |live| {
            let tx = &live.tx;
            live.inflight_requests.retain(|req| {
                if req.piece_index == stolen_idx {
                    let _ = tx.send(WriterRequest::Message(Message::Cancel(Request {
                        index: stolen_idx.get(),
                        begin: req.offset,
                        length: req.size,
                    })));
                    false
                } else {
                    true
                }
            });
        });
    }
}
