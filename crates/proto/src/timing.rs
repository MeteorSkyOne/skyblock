//! Protocol timers (SPEC §3.12), in microseconds.

use crate::Micros;

pub const MS: Micros = 1_000;
pub const SECOND: Micros = 1_000_000;

/// First handshake retry delay; doubles per attempt up to the maximum.
pub const HANDSHAKE_RETRY: Micros = SECOND;
pub const HANDSHAKE_RETRY_MAX: Micros = 8 * SECOND;
/// Give up (and report) after this long without a response.
pub const HANDSHAKE_GIVE_UP: Micros = 30 * SECOND;

/// PING interval while data flowed recently / while idle.
pub const PING_ACTIVE: Micros = SECOND;
pub const PING_IDLE: Micros = 10 * SECOND;
/// Data within this window counts as "active" for the PING schedule.
pub const ACTIVE_WINDOW: Micros = 10 * SECOND;
/// Random jitter applied to PING intervals, in percent.
pub const PING_JITTER_PCT: u64 = 20;

/// A path with no valid packet for this long is down; while idle (PINGs
/// every 10s ± 20%) the limit covers one whole PING interval more.
pub const PATH_DOWN: Micros = 5 * SECOND;
pub const PATH_DOWN_IDLE: Micros = PATH_DOWN + PING_IDLE * (100 + PING_JITTER_PCT) / 100;
/// The server forgets a path down for this long.
pub const PATH_FORGET: Micros = 60 * SECOND;

/// Client re-handshakes after this long without any valid packet.
pub const CLIENT_SESSION_DEAD: Micros = 15 * SECOND;
/// Server drops a session after this long without any valid packet.
pub const SERVER_SESSION_EXPIRE: Micros = 180 * SECOND;

pub const UDP_NAT_TIMEOUT: Micros = 300 * SECOND;

/// STATS interval while active / idle.
pub const STATS_ACTIVE: Micros = SECOND;
pub const STATS_IDLE: Micros = 10 * SECOND;

/// Flow classification (SPEC §4.1): rate window, how long a bulk flow must
/// stay slow before it counts as a game flow again, and when an idle
/// flow's state is dropped.
pub const FLOW_WINDOW: Micros = SECOND;
pub const BULK_EXIT_HOLD: Micros = 5 * SECOND;
pub const FLOW_IDLE: Micros = 60 * SECOND;

/// Path ranking (SPEC §3.8): score = srtt + JITTER_WEIGHT × rttvar +
/// LOSS_PENALTY × loss, and the margin a path must win by to replace the
/// current best one.
pub const JITTER_WEIGHT: Micros = 2;
pub const LOSS_PENALTY: Micros = 50 * MS;
pub const PATH_HYSTERESIS: Micros = 500;
