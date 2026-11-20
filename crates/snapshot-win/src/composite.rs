//! A disk assembled from the raw device plus per-partition overlays
//! (snapshot devices). Reads inside an overlaid partition go to its
//! snapshot; everything else goes to the raw disk.

use std::io;
use std::sync::Arc;

use core_format::io::ReadAt;
use core_format::partition::PartitionTable;
use engine::{CapturePlan, DiskInfo, DiskSource};

pub type SharedReader = Arc<dyn ReadAt + Send + Sync>;

#[derive(Clone)]
pub struct Overlay {
    /// Absolute disk offset where the partition starts.
    pub start: u64,
    pub len: u64,
    /// Snapshot device; offset 0 = partition start.
    pub device: SharedReader,
}

pub struct CompositeDisk {
    pub info: DiskInfo,
    pub raw: SharedReader,
    overlays: Vec<Overlay>,
    pub plan: CapturePlan,
}

impl CompositeDisk {
    pub fn new(info: DiskInfo, raw: SharedReader, mut overlays: Vec<Overlay>, plan: CapturePlan) -> io::Result<Self> {
        overlays.sort_by_key(|o| o.start);
        for w in overlays.windows(2) {
            if w[0].start + w[0].len > w[1].start {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "overlapping snapshot overlays"));
            }
        }
        Ok(CompositeDisk { info, raw, overlays, plan })
    }
}

impl DiskSource for CompositeDisk {
    fn info(&self) -> DiskInfo {
        self.info.clone()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut pos = offset;
        let end = offset + buf.len() as u64;
        while pos < end {
            let done = (pos - offset) as usize;
            // Overlay containing pos, or the next overlay after pos.
            let cur = self.overlays.iter().find(|o| pos >= o.start && pos < o.start + o.len);
            let (stop, dev, dev_off): (u64, &SharedReader, u64) = match cur {
                Some(o) => ((o.start + o.len).min(end), &o.device, pos - o.start),
                None => {
                    let next = self.overlays.iter().filter(|o| o.start > pos).map(|o| o.start).min().unwrap_or(u64::MAX);
                    (next.min(end), &self.raw, pos)
                }
            };
            let n = (stop - pos) as usize;
            dev.read_at(dev_off, &mut buf[done..done + n])?;
            pos = stop;
        }
        Ok(())
    }

    fn capture_plan(&self, _table: &PartitionTable) -> io::Result<CapturePlan> {
        Ok(self.plan.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_reads_across_boundaries() {
        let raw: SharedReader = Arc::new(vec![b'r'; 100]);
        let snap_a: SharedReader = Arc::new((0..20u8).collect::<Vec<u8>>());
        let snap_b: SharedReader = Arc::new(vec![b'b'; 10]);
        let d = CompositeDisk::new(
            DiskInfo { size: 100, ..Default::default() },
            raw,
            vec![Overlay { start: 60, len: 10, device: snap_b }, Overlay { start: 10, len: 20, device: snap_a }],
            CapturePlan::default(),
        )
        .unwrap();
        let mut buf = vec![0u8; 100];
        d.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..10], &[b'r'; 10]);
        assert_eq!(&buf[10..30], &(0..20u8).collect::<Vec<u8>>()[..]);
        assert_eq!(&buf[30..60], &[b'r'; 30]);
        assert_eq!(&buf[60..70], &[b'b'; 10]);
        assert_eq!(&buf[70..], &[b'r'; 30]);
        let mut small = [0u8; 4];
        d.read_at(28, &mut small).unwrap();
        assert_eq!(small, [18, 19, b'r', b'r']);
    }

    #[test]
    fn rejects_overlapping_overlays() {
        let r: SharedReader = Arc::new(vec![0u8; 10]);
        let o = |s| Overlay { start: s, len: 5, device: r.clone() };
        assert!(CompositeDisk::new(DiskInfo::default(), r.clone(), vec![o(0), o(3)], CapturePlan::default()).is_err());
    }
}
