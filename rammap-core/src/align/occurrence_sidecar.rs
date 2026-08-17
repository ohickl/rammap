//! Fixed-width occurrence-count sidecars for exact multi-shard calibration.
//!
//! Records are ordered by `(bucket, hash)`. This is the order produced by
//! [`crate::align::index::IndexBuilder::finish_with_occurrence_counts`], so a
//! builder can stream records directly to disk without retaining a second
//! catalog-sized collection. Separate shard sidecars can subsequently be
//! merged bucket-by-bucket.

use std::io::{self, ErrorKind, Read, Write};

const MAGIC: &[u8; 4] = b"RXOC";
const TRAILER_MAGIC: &[u8; 4] = b"END1";
pub const OCCURRENCE_SIDECAR_VERSION: u32 = 1;
const HEADER_BYTES: usize = 84;
const RECORD_BYTES: usize = 16;
const TRAILER_BYTES: usize = 20;
const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OccurrenceSidecarMetadata {
    pub bucket_bits: u32,
    pub shard_id: u32,
    pub shard_count: u32,
    pub parameter_digest: [u8; 32],
    pub target_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OccurrenceRecord {
    pub bucket: u32,
    pub hash: u64,
    pub count: u32,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn checksum_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= byte as u64;
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn read_exact<const N: usize, R: Read>(reader: &mut R) -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn validate_header_bytes(bytes: &[u8; HEADER_BYTES], expected: Option<&OccurrenceSidecarMetadata>) -> io::Result<OccurrenceSidecarMetadata> {
    if &bytes[..4] != MAGIC {
        return Err(invalid("invalid occurrence sidecar magic"));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != OCCURRENCE_SIDECAR_VERSION {
        return Err(invalid(format!("unsupported occurrence sidecar version {version}")));
    }
    let metadata = OccurrenceSidecarMetadata {
        bucket_bits: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        shard_id: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        shard_count: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        parameter_digest: bytes[20..52].try_into().unwrap(),
        target_digest: bytes[52..84].try_into().unwrap(),
    };
    if metadata.bucket_bits > 63 || metadata.shard_count == 0 || metadata.shard_id >= metadata.shard_count {
        return Err(invalid("invalid occurrence sidecar shard metadata"));
    }
    if let Some(expected) = expected {
        if &metadata != expected {
            return Err(invalid("occurrence sidecar metadata mismatch"));
        }
    }
    Ok(metadata)
}

/// Append-only writer for one shard's pre-cap occurrence counts.
pub struct OccurrenceSidecarWriter<W> {
    writer: W,
    metadata: OccurrenceSidecarMetadata,
    checksum: u64,
    record_count: u64,
    last_key: Option<(u32, u64)>,
}

impl<W: Write> OccurrenceSidecarWriter<W> {
    pub fn new(mut writer: W, metadata: OccurrenceSidecarMetadata) -> io::Result<Self> {
        if metadata.bucket_bits > 63 || metadata.shard_count == 0 || metadata.shard_id >= metadata.shard_count {
            return Err(invalid("invalid occurrence sidecar metadata"));
        }
        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(MAGIC);
        header[4..8].copy_from_slice(&OCCURRENCE_SIDECAR_VERSION.to_le_bytes());
        header[8..12].copy_from_slice(&metadata.bucket_bits.to_le_bytes());
        header[12..16].copy_from_slice(&metadata.shard_id.to_le_bytes());
        header[16..20].copy_from_slice(&metadata.shard_count.to_le_bytes());
        header[20..52].copy_from_slice(&metadata.parameter_digest);
        header[52..84].copy_from_slice(&metadata.target_digest);
        writer.write_all(&header)?;
        Ok(Self { writer, metadata, checksum: checksum_update(FNV_OFFSET, &header), record_count: 0, last_key: None })
    }

    pub fn write_record(&mut self, record: OccurrenceRecord) -> io::Result<()> {
        let mask = if self.metadata.bucket_bits == 63 { u64::MAX >> 1 } else { (1u64 << self.metadata.bucket_bits) - 1 };
        if u64::from(record.bucket) != record.hash & mask {
            return Err(invalid("occurrence record bucket does not match hash"));
        }
        if record.count == 0 {
            return Err(invalid("occurrence record count must be nonzero"));
        }
        if let Some(last) = self.last_key {
            if (record.bucket, record.hash) <= last {
                return Err(invalid("occurrence records are not strictly ordered"));
            }
        }
        let mut bytes = [0u8; RECORD_BYTES];
        bytes[..4].copy_from_slice(&record.bucket.to_le_bytes());
        bytes[4..12].copy_from_slice(&record.hash.to_le_bytes());
        bytes[12..16].copy_from_slice(&record.count.to_le_bytes());
        self.writer.write_all(&bytes)?;
        self.checksum = checksum_update(self.checksum, &bytes);
        self.record_count = self.record_count.checked_add(1).ok_or_else(|| invalid("occurrence sidecar record count overflow"))?;
        self.last_key = Some((record.bucket, record.hash));
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        let mut trailer = [0u8; TRAILER_BYTES];
        trailer[..4].copy_from_slice(TRAILER_MAGIC);
        trailer[4..12].copy_from_slice(&self.record_count.to_le_bytes());
        trailer[12..20].copy_from_slice(&self.checksum.to_le_bytes());
        self.writer.write_all(&trailer)?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}

/// Streaming reader that validates ordering, checksums, and the committed
/// trailer before accepting a sidecar as complete.
pub struct OccurrenceSidecarReader<R> {
    reader: R,
    metadata: OccurrenceSidecarMetadata,
    checksum: u64,
    expected_records: Option<u64>,
    records_read: u64,
    last_key: Option<(u32, u64)>,
    finished: bool,
}

impl<R: Read> OccurrenceSidecarReader<R> {
    pub fn new(mut reader: R, expected: Option<&OccurrenceSidecarMetadata>) -> io::Result<Self> {
        let header = read_exact::<HEADER_BYTES, _>(&mut reader)?;
        let metadata = validate_header_bytes(&header, expected)?;
        Ok(Self { reader, metadata, checksum: checksum_update(FNV_OFFSET, &header), expected_records: None, records_read: 0, last_key: None, finished: false })
    }

    pub fn metadata(&self) -> &OccurrenceSidecarMetadata { &self.metadata }

    pub fn next_record(&mut self) -> io::Result<Option<OccurrenceRecord>> {
        if self.finished { return Ok(None); }
        if let Some(expected) = self.expected_records {
            if self.records_read == expected {
                self.finish_trailer()?;
                return Ok(None);
            }
        }

        let mut first = [0u8; 4];
        self.reader.read_exact(&mut first)?;
        if &first == TRAILER_MAGIC {
            let mut trailer = [0u8; TRAILER_BYTES];
            trailer[..4].copy_from_slice(&first);
            self.reader.read_exact(&mut trailer[4..])?;
            self.finish_trailer_bytes(&trailer)?;
            return Ok(None);
        }
        let mut bytes = [0u8; RECORD_BYTES];
        bytes[..4].copy_from_slice(&first);
        self.reader.read_exact(&mut bytes[4..])?;
        let record = OccurrenceRecord {
            bucket: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            hash: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            count: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        };
        let mask = if self.metadata.bucket_bits == 63 { u64::MAX >> 1 } else { (1u64 << self.metadata.bucket_bits) - 1 };
        if u64::from(record.bucket) != record.hash & mask || record.count == 0 {
            return Err(invalid("invalid occurrence sidecar record"));
        }
        if let Some(last) = self.last_key {
            if (record.bucket, record.hash) <= last {
                return Err(invalid("occurrence sidecar records are not ordered"));
            }
        }
        self.checksum = checksum_update(self.checksum, &bytes);
        self.records_read = self.records_read.checked_add(1).ok_or_else(|| invalid("occurrence sidecar record count overflow"))?;
        self.last_key = Some((record.bucket, record.hash));
        Ok(Some(record))
    }

    fn finish_trailer(&mut self) -> io::Result<()> {
        let trailer = read_exact::<TRAILER_BYTES, _>(&mut self.reader)?;
        self.finish_trailer_bytes(&trailer)
    }

    fn finish_trailer_bytes(&mut self, trailer: &[u8; TRAILER_BYTES]) -> io::Result<()> {
        if &trailer[..4] != TRAILER_MAGIC {
            return Err(invalid("missing occurrence sidecar trailer"));
        }
        let expected_count = u64::from_le_bytes(trailer[4..12].try_into().unwrap());
        let expected_checksum = u64::from_le_bytes(trailer[12..20].try_into().unwrap());
        if expected_count != self.records_read || expected_checksum != self.checksum {
            return Err(invalid("occurrence sidecar trailer checksum or count mismatch"));
        }
        let mut trailing = [0u8; 1];
        if self.reader.read(&mut trailing)? != 0 {
            return Err(invalid("trailing bytes after occurrence sidecar trailer"));
        }
        self.expected_records = Some(expected_count);
        self.finished = true;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        while self.next_record()?.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn metadata() -> OccurrenceSidecarMetadata {
        OccurrenceSidecarMetadata { bucket_bits: 4, shard_id: 0, shard_count: 1, parameter_digest: [1; 32], target_digest: [2; 32] }
    }

    #[test]
    fn round_trip_preserves_fixed_width_records() {
        let mut bytes = Vec::new();
        let mut writer = OccurrenceSidecarWriter::new(&mut bytes, metadata()).unwrap();
        writer.write_record(OccurrenceRecord { bucket: 1, hash: 0x21, count: 3 }).unwrap();
        writer.write_record(OccurrenceRecord { bucket: 2, hash: 0x32, count: 9 }).unwrap();
        writer.finish().unwrap();

        let mut reader = OccurrenceSidecarReader::new(Cursor::new(bytes), Some(&metadata())).unwrap();
        assert_eq!(reader.next_record().unwrap(), Some(OccurrenceRecord { bucket: 1, hash: 0x21, count: 3 }));
        assert_eq!(reader.next_record().unwrap(), Some(OccurrenceRecord { bucket: 2, hash: 0x32, count: 9 }));
        assert_eq!(reader.next_record().unwrap(), None);
    }

    #[test]
    fn corruption_and_uncommitted_sidecars_fail_closed() {
        let mut bytes = Vec::new();
        let mut writer = OccurrenceSidecarWriter::new(&mut bytes, metadata()).unwrap();
        writer.write_record(OccurrenceRecord { bucket: 1, hash: 0x21, count: 3 }).unwrap();
        writer.finish().unwrap();
        bytes[100] ^= 1;
        assert!(OccurrenceSidecarReader::new(Cursor::new(bytes), None).unwrap().finish().is_err());

        let mut truncated = Vec::new();
        let mut writer = OccurrenceSidecarWriter::new(&mut truncated, metadata()).unwrap();
        writer.write_record(OccurrenceRecord { bucket: 1, hash: 0x21, count: 3 }).unwrap();
        writer.finish().unwrap();
        truncated.truncate(truncated.len() - 1);
        assert!(OccurrenceSidecarReader::new(Cursor::new(truncated), None).unwrap().finish().is_err());
    }
}
