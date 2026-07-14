use crate::LinkError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionBudget {
    pub max_memory_bytes: usize,
    pub max_bandwidth_bytes_per_second: u64,
    pub max_channels: usize,
    pub max_send_queue_frames: usize,
    pub max_resume_channels: usize,
    pub max_pending_replays: usize,
    pub max_maintenance_operations_per_tick: usize,
}

impl Default for ConnectionBudget {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_bandwidth_bytes_per_second: 16 * 1024 * 1024,
            max_channels: 64,
            max_send_queue_frames: 512,
            max_resume_channels: 64,
            max_pending_replays: 128,
            max_maintenance_operations_per_tick: 8,
        }
    }
}

impl ConnectionBudget {
    pub fn validate(self) -> Result<Self, LinkError> {
        if self.max_memory_bytes == 0
            || self.max_bandwidth_bytes_per_second == 0
            || self.max_channels == 0
            || self.max_send_queue_frames == 0
            || self.max_resume_channels == 0
            || self.max_pending_replays == 0
            || self.max_maintenance_operations_per_tick == 0
        {
            return Err(LinkError::InvalidInput(
                "connection budget values must be positive",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceMode {
    Normal,
    Reduced,
    Paused,
}

#[derive(Debug)]
pub struct MaintenanceBudget {
    maximum_per_tick: usize,
    remaining: usize,
    mode: MaintenanceMode,
}

impl MaintenanceBudget {
    pub fn new(connection: ConnectionBudget) -> Result<Self, LinkError> {
        let connection = connection.validate()?;
        Ok(Self {
            maximum_per_tick: connection.max_maintenance_operations_per_tick,
            remaining: connection.max_maintenance_operations_per_tick,
            mode: MaintenanceMode::Normal,
        })
    }

    pub fn set_mode(&mut self, mode: MaintenanceMode) {
        self.mode = mode;
    }

    pub fn begin_tick(&mut self) {
        self.remaining = match self.mode {
            MaintenanceMode::Normal => self.maximum_per_tick,
            MaintenanceMode::Reduced => self.maximum_per_tick.div_ceil(4),
            MaintenanceMode::Paused => 0,
        };
    }

    pub fn try_consume(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}
