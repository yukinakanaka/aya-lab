#[repr(C)]
pub struct SharedState {
    pub per_event_count: u32,
    pub total_count: u32,
}
