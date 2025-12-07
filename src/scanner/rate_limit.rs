use std::time::Instant;

pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(rate: u32) -> Self {
        Self {
            rate: rate as f64,
            capacity: rate as f64,
            tokens: rate as f64,
            last_update: Instant::now(),
        }
    }

    pub async fn acquire(&mut self) {
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_update).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last_update = now;

            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }

            let missing = 1.0 - self.tokens;
            let wait_time = missing / self.rate;
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait_time)).await;
        }
    }
}
