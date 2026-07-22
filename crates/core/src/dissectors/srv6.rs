
pub struct SrhDummy;
impl SrhDummy {
    pub fn note(&self) -> String { "".into() }
}
pub fn find(_payload: &[u8]) -> Option<SrhDummy> { None }
