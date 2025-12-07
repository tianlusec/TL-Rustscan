


pub const HTTP_BODY_SIZE_LIMIT: usize = 1024 * 1024; 


pub const BANNER_INITIAL_SIZE: usize = 512;
pub const BANNER_MAX_SIZE: usize = 8192;


pub const MAX_RETRY_QUEUE_SIZE: usize = 100_000;


pub const MIN_RETRY_CONCURRENCY: usize = 10;
pub const RETRY_CONCURRENCY_DIVISOR: usize = 5;
pub const RETRY_TIMEOUT_MULTIPLIER: u64 = 2;


pub const DNS_RESOLVE_CONCURRENCY: usize = 500;


pub const DEFAULT_DIR_CONCURRENCY_SMALL: usize = 20;
pub const DEFAULT_DIR_CONCURRENCY_LARGE: usize = 50;
pub const DIR_DICT_SIZE_THRESHOLD: usize = 100;
pub const DIR_SCAN_GLOBAL_LIMIT: usize = 100;
pub const DIR_SCAN_CONCURRENCY_HIGH: usize = 50;
pub const DIR_SCAN_CONCURRENCY_LOW: usize = 20;
