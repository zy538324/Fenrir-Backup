//! Ransomware guard: flag a backup whose changed-data ratio jumps far above
//! the machine's baseline while the new data is incompressible (encrypted
//! data does not compress). A flag puts the repository on hold: no
//! retention or pruning runs until an administrator releases it, so the
//! images from before the event cannot be aged out.

/// Change statistics of one image.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub chunks_total: u64,
    pub chunks_new: u64,
    pub bytes_new_raw: u64,
    pub bytes_new_stored: u64,
}

impl Stats {
    pub fn change_ratio(&self) -> f64 {
        if self.chunks_total == 0 {
            0.0
        } else {
            self.chunks_new as f64 / self.chunks_total as f64
        }
    }
    /// Stored / raw size of the new data: about 1.0 when incompressible.
    pub fn incompressibility(&self) -> f64 {
        if self.bytes_new_raw == 0 {
            0.0
        } else {
            self.bytes_new_stored as f64 / self.bytes_new_raw as f64
        }
    }
}

/// `history`: earlier images of the same machine, any order. Returns the
/// reason when `current` looks like mass encryption.
pub fn evaluate(history: &[Stats], current: &Stats) -> Option<String> {
    let ratio = current.change_ratio();
    let incompressible = current.incompressibility();
    // Too little new data to judge (e.g. a quiet day).
    if current.chunks_new < 8 {
        return None;
    }
    let mut ratios: Vec<f64> = history
        .iter()
        .filter(|h| h.chunks_total > 0)
        .map(Stats::change_ratio)
        .collect();
    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if ratios.len() >= 5 {
        let baseline = ratios[ratios.len() / 2];
        let limit = (3.0 * baseline).max(0.25);
        if ratio > limit && incompressible > 0.9 {
            return Some(format!(
                "{:.0}% of the data changed (usual: {:.0}%) and the new data does not compress ({:.0}% of original size): possible mass encryption",
                ratio * 100.0,
                baseline * 100.0,
                incompressible * 100.0
            ));
        }
        None
    } else if !ratios.is_empty() && ratio > 0.5 && incompressible > 0.95 {
        Some(format!(
            "{:.0}% of the data changed since the previous backup and the new data does not compress: possible mass encryption",
            ratio * 100.0
        ))
    } else {
        // First backup of a machine: everything is new by definition.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(total: u64, new: u64, raw: u64, stored: u64) -> Stats {
        Stats {
            chunks_total: total,
            chunks_new: new,
            bytes_new_raw: raw,
            bytes_new_stored: stored,
        }
    }

    #[test]
    fn normal_days_pass() {
        let hist: Vec<Stats> = (0..10).map(|_| s(1000, 30, 30, 12)).collect();
        assert!(evaluate(&hist, &s(1000, 40, 40, 16)).is_none());
        // Big but compressible change (e.g. an OS update) passes.
        assert!(evaluate(&hist, &s(1000, 600, 600, 250)).is_none());
    }

    #[test]
    fn mass_encryption_is_flagged() {
        let hist: Vec<Stats> = (0..10).map(|_| s(1000, 30, 30, 12)).collect();
        let r = evaluate(&hist, &s(1000, 700, 700, 699)).unwrap();
        assert!(r.contains("70%") && r.contains("encryption"), "{r}");
    }

    #[test]
    fn first_backup_never_flagged_and_short_history_uses_strict_rule() {
        assert!(evaluate(&[], &s(1000, 1000, 1000, 1000)).is_none());
        let hist = [s(1000, 20, 20, 8)];
        assert!(evaluate(&hist, &s(1000, 800, 800, 790)).is_some());
        assert!(evaluate(&hist, &s(1000, 400, 400, 399)).is_none());
        // Tiny changes are not judged.
        assert!(evaluate(&hist, &s(1000, 5, 5, 5)).is_none());
    }
}
