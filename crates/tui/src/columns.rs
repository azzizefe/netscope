//! User-selectable packet-list columns for the TUI (ROADMAP §6.1). The
//! packet table can show any subset of the standard columns; the Columns
//! overlay (`c`) toggles them with the number keys. Info is never hidden — a
//! packet list with no description column would be useless — so it isn't
//! offered as a toggle.

/// Which optional columns are currently shown. `Info` is always rendered and
/// is not part of this set.
#[derive(Debug, Clone, Copy)]
pub struct Columns {
    pub num: bool,
    pub time: bool,
    pub source: bool,
    pub destination: bool,
    pub protocol: bool,
    pub length: bool,
}

impl Default for Columns {
    fn default() -> Self {
        Self {
            num: true,
            time: true,
            source: true,
            destination: true,
            protocol: true,
            length: false,
        }
    }
}

/// A toggleable column, in the order shown in the overlay and the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    Num,
    Time,
    Source,
    Destination,
    Protocol,
    Length,
}

impl Column {
    /// The toggleable columns, in display order — index + 1 is the hotkey.
    pub const ALL: [Column; 6] = [
        Column::Num,
        Column::Time,
        Column::Source,
        Column::Destination,
        Column::Protocol,
        Column::Length,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Column::Num => "No.",
            Column::Time => "Time",
            Column::Source => "Source",
            Column::Destination => "Destination",
            Column::Protocol => "Protocol",
            Column::Length => "Length",
        }
    }
}

impl Columns {
    /// Whether `col` is currently shown.
    pub fn is_on(&self, col: Column) -> bool {
        match col {
            Column::Num => self.num,
            Column::Time => self.time,
            Column::Source => self.source,
            Column::Destination => self.destination,
            Column::Protocol => self.protocol,
            Column::Length => self.length,
        }
    }

    /// Flip `col` on/off.
    pub fn toggle(&mut self, col: Column) {
        match col {
            Column::Num => self.num = !self.num,
            Column::Time => self.time = !self.time,
            Column::Source => self.source = !self.source,
            Column::Destination => self.destination = !self.destination,
            Column::Protocol => self.protocol = !self.protocol,
            Column::Length => self.length = !self.length,
        }
    }

    /// Toggle by 1-based hotkey (`1`..=`6`); out-of-range indices are ignored.
    pub fn toggle_index(&mut self, one_based: usize) {
        if let Some(col) = Column::ALL.get(one_based.wrapping_sub(1)) {
            self.toggle(*col);
        }
    }
}
