//! Durable, fixed-width global occurrence policy for partitioned mapping.
//!
//! The policy is sorted by `(bucket, hash)` and is intentionally kept on disk.
//! A mapper uses the authenticated bucket ranges and positional reads to look
//! up a global count without retaining a second catalog-sized hash table.

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
use std::os::unix::fs::FileExt;

const MAGIC: &[u8; 4] = b"RXGP";
const TRAILER_MAGIC: &[u8; 4] = b"END1";
pub const GLOBAL_OCCURRENCE_POLICY_VERSION: u32 = 1;
const HEADER_BYTES: u64 = 80;
const RECORD_BYTES: u64 = 24;
const TRAILER_FIXED_BYTES: u64 = 24;
const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalOccurrencePolicyMetadata {
    pub bucket_bits: u32,
    pub shard_count: u32,
    pub parameter_digest: [u8; 32],
    pub target_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalOccurrenceRecord {
    pub bucket: u32,
    pub hash: u64,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalOccurrencePolicyFacts {
    pub bytes: u64,
    pub checksum: u64,
    pub record_count: u64,
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

fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        while !bytes.is_empty() {
            let count = file.read_at(bytes, offset)?;
            if count == 0 {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "global occurrence policy is truncated"));
            }
            bytes = &mut bytes[count..];
            offset = offset
                .checked_add(count as u64)
                .ok_or_else(|| invalid("global occurrence policy offset overflow"))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut clone = file.try_clone()?;
        clone.seek(SeekFrom::Start(offset))?;
        clone.read_exact(bytes)
    }
}

fn validate_metadata(metadata: &GlobalOccurrencePolicyMetadata) -> io::Result<()> {
    // The current fixed-width trailer stores one `(start, count)` pair per
    // bucket.  Keep the geometry bounded independently of attacker- or
    // caller-supplied metadata; the partition orchestrator currently uses
    // ten bits, and larger tables would be an unmeasured allocation change.
    if metadata.bucket_bits > 20 || metadata.shard_count == 0 {
        return Err(invalid("invalid global occurrence policy metadata"));
    }
    Ok(())
}

/// Streaming writer for one globally merged occurrence policy.
pub struct GlobalOccurrencePolicyWriter {
    writer: BufWriter<File>,
    metadata: GlobalOccurrencePolicyMetadata,
    bucket_count: usize,
    bucket_starts: Vec<u64>,
    bucket_counts: Vec<u64>,
    record_count: u64,
    last_key: Option<(u32, u64)>,
}

impl GlobalOccurrencePolicyWriter {
    pub fn create(path: &Path, metadata: GlobalOccurrencePolicyMetadata) -> io::Result<Self> {
        validate_metadata(&metadata)?;
        let bucket_count = 1usize
            .checked_shl(metadata.bucket_bits)
            .ok_or_else(|| invalid("global occurrence policy bucket count overflow"))?;
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&[0u8; HEADER_BYTES as usize])?;
        Ok(Self {
            writer,
            metadata,
            bucket_count,
            bucket_starts: vec![0; bucket_count],
            bucket_counts: vec![0; bucket_count],
            record_count: 0,
            last_key: None,
        })
    }

    pub fn write_record(&mut self, record: GlobalOccurrenceRecord) -> io::Result<()> {
        let mask = (1u64 << self.metadata.bucket_bits) - 1;
        if u64::from(record.bucket) != record.hash & mask || record.count == 0 {
            return Err(invalid("invalid global occurrence policy record"));
        }
        if let Some(last) = self.last_key {
            if (record.bucket, record.hash) <= last {
                return Err(invalid("global occurrence policy records are not ordered"));
            }
        }
        let bucket = record.bucket as usize;
        if bucket >= self.bucket_count {
            return Err(invalid("global occurrence policy bucket is out of range"));
        }
        if self.bucket_counts[bucket] == 0 {
            self.bucket_starts[bucket] = self.record_count;
        }
        let mut bytes = [0u8; RECORD_BYTES as usize];
        bytes[..4].copy_from_slice(&record.bucket.to_le_bytes());
        bytes[4..12].copy_from_slice(&record.hash.to_le_bytes());
        bytes[12..20].copy_from_slice(&record.count.to_le_bytes());
        self.writer.write_all(&bytes)?;
        self.bucket_counts[bucket] = self.bucket_counts[bucket]
            .checked_add(1)
            .ok_or_else(|| invalid("global occurrence policy bucket count overflow"))?;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| invalid("global occurrence policy record count overflow"))?;
        self.last_key = Some((record.bucket, record.hash));
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<GlobalOccurrencePolicyFacts> {
        self.writer.flush()?;
        let mut file = self
            .writer
            .into_inner()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut header = [0u8; HEADER_BYTES as usize];
        header[..4].copy_from_slice(MAGIC);
        header[4..8].copy_from_slice(&GLOBAL_OCCURRENCE_POLICY_VERSION.to_le_bytes());
        header[8..12].copy_from_slice(&self.metadata.bucket_bits.to_le_bytes());
        header[12..16].copy_from_slice(&self.metadata.shard_count.to_le_bytes());
        header[16..48].copy_from_slice(&self.metadata.parameter_digest);
        header[48..80].copy_from_slice(&self.metadata.target_digest);
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.flush()?;

        let data_bytes = HEADER_BYTES
            .checked_add(
                self.record_count
                    .checked_mul(RECORD_BYTES)
                    .ok_or_else(|| invalid("global occurrence policy length overflow"))?,
            )
            .ok_or_else(|| invalid("global occurrence policy length overflow"))?;
        file.seek(SeekFrom::Start(0))?;
        let mut checksum_reader = BufReader::new(file.try_clone()?);
        let mut checksum = FNV_OFFSET;
        let mut remaining = data_bytes;
        let mut buffer = [0u8; 1024 * 1024];
        while remaining > 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            checksum_reader.read_exact(&mut buffer[..wanted])?;
            checksum = checksum_update(checksum, &buffer[..wanted]);
            remaining -= wanted as u64;
        }

        let mut trailer = Vec::with_capacity(
            TRAILER_FIXED_BYTES as usize + self.bucket_count * 16,
        );
        trailer.extend_from_slice(TRAILER_MAGIC);
        trailer.extend_from_slice(&self.record_count.to_le_bytes());
        trailer.extend_from_slice(&checksum.to_le_bytes());
        trailer.extend_from_slice(&(self.bucket_count as u32).to_le_bytes());
        for (&start, &count) in self.bucket_starts.iter().zip(&self.bucket_counts) {
            trailer.extend_from_slice(&start.to_le_bytes());
            trailer.extend_from_slice(&count.to_le_bytes());
        }
        file.seek(SeekFrom::Start(data_bytes))?;
        file.write_all(&trailer)?;
        file.sync_all()?;
        let bytes = data_bytes
            .checked_add(trailer.len() as u64)
            .ok_or_else(|| invalid("global occurrence policy length overflow"))?;
        Ok(GlobalOccurrencePolicyFacts {
            bytes,
            checksum,
            record_count: self.record_count,
        })
    }
}

/// Immutable read-only policy view. The only mutable state is a sticky error
/// flag used to fail closed after an unexpected positional read failure.
pub struct GlobalOccurrencePolicy {
    file: File,
    metadata: GlobalOccurrencePolicyMetadata,
    facts: GlobalOccurrencePolicyFacts,
    bucket_ranges: Vec<(u64, u64)>,
    invalid_read: AtomicBool,
}

impl GlobalOccurrencePolicy {
    pub fn open(path: &Path, expected: &GlobalOccurrencePolicyMetadata) -> io::Result<Self> {
        validate_metadata(expected)?;
        let file = File::open(path)?;
        let file_bytes = file.metadata()?.len();
        let mut header = [0u8; HEADER_BYTES as usize];
        read_exact_at(&file, &mut header, 0)?;
        if &header[..4] != MAGIC
            || u32::from_le_bytes(header[4..8].try_into().unwrap())
                != GLOBAL_OCCURRENCE_POLICY_VERSION
        {
            return Err(invalid("global occurrence policy version or magic is invalid"));
        }
        let metadata = GlobalOccurrencePolicyMetadata {
            bucket_bits: u32::from_le_bytes(header[8..12].try_into().unwrap()),
            shard_count: u32::from_le_bytes(header[12..16].try_into().unwrap()),
            parameter_digest: header[16..48].try_into().unwrap(),
            target_digest: header[48..80].try_into().unwrap(),
        };
        if &metadata != expected {
            return Err(invalid("global occurrence policy identity mismatch"));
        }
        let bucket_count = 1usize
            .checked_shl(metadata.bucket_bits)
            .ok_or_else(|| invalid("global occurrence policy bucket count overflow"))?;
        let trailer_bytes = TRAILER_FIXED_BYTES
            .checked_add((bucket_count as u64).checked_mul(16).ok_or_else(|| invalid("global occurrence policy trailer length overflow"))?)
            .ok_or_else(|| invalid("global occurrence policy trailer length overflow"))?;
        if file_bytes < HEADER_BYTES + trailer_bytes {
            return Err(invalid("global occurrence policy is truncated"));
        }
        let trailer_offset = file_bytes - trailer_bytes;
        let mut trailer = vec![0u8; trailer_bytes as usize];
        read_exact_at(&file, &mut trailer, trailer_offset)?;
        if &trailer[..4] != TRAILER_MAGIC
            || u32::from_le_bytes(trailer[20..24].try_into().unwrap()) != bucket_count as u32
        {
            return Err(invalid("global occurrence policy trailer is invalid"));
        }
        let record_count = u64::from_le_bytes(trailer[4..12].try_into().unwrap());
        let checksum = u64::from_le_bytes(trailer[12..20].try_into().unwrap());
        let data_bytes = HEADER_BYTES
            .checked_add(record_count.checked_mul(RECORD_BYTES).ok_or_else(|| invalid("global occurrence policy record length overflow"))?)
            .ok_or_else(|| invalid("global occurrence policy record length overflow"))?;
        if data_bytes != trailer_offset {
            return Err(invalid("global occurrence policy record and trailer lengths disagree"));
        }
        let mut bucket_ranges = Vec::with_capacity(bucket_count);
        let mut offset = 24usize;
        for _ in 0..bucket_count {
            let start = u64::from_le_bytes(trailer[offset..offset + 8].try_into().unwrap());
            let count = u64::from_le_bytes(trailer[offset + 8..offset + 16].try_into().unwrap());
            offset += 16;
            if start.checked_add(count).ok_or_else(|| invalid("global occurrence policy bucket range overflow"))? > record_count {
                return Err(invalid("global occurrence policy bucket range is invalid"));
            }
            bucket_ranges.push((start, count));
        }
        let mut reader = BufReader::new(file.try_clone()?);
        let mut checksum_reader = FNV_OFFSET;
        let mut remaining = data_bytes;
        let mut buffer = [0u8; 1024 * 1024];
        while remaining > 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..wanted])?;
            checksum_reader = checksum_update(checksum_reader, &buffer[..wanted]);
            remaining -= wanted as u64;
        }
        if checksum_reader != checksum {
            return Err(invalid("global occurrence policy checksum mismatch"));
        }
        Ok(Self {
            file,
            metadata,
            facts: GlobalOccurrencePolicyFacts { bytes: file_bytes, checksum, record_count },
            bucket_ranges,
            invalid_read: AtomicBool::new(false),
        })
    }

    pub fn metadata(&self) -> &GlobalOccurrencePolicyMetadata { &self.metadata }

    pub fn facts(&self) -> GlobalOccurrencePolicyFacts { self.facts }

    fn record_at(&self, ordinal: u64) -> io::Result<GlobalOccurrenceRecord> {
        let offset = HEADER_BYTES
            .checked_add(ordinal.checked_mul(RECORD_BYTES).ok_or_else(|| invalid("global occurrence policy offset overflow"))?)
            .ok_or_else(|| invalid("global occurrence policy offset overflow"))?;
        let mut bytes = [0u8; RECORD_BYTES as usize];
        read_exact_at(&self.file, &mut bytes, offset)?;
        Ok(GlobalOccurrenceRecord {
            bucket: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            hash: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            count: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        })
    }

    /// Return the global count for a hash, or `None` when it is absent from
    /// the complete global catalog. An unexpected read error is sticky and is
    /// reported by [`Self::ensure_valid`].
    pub fn lookup(&self, hash: u64) -> Option<u64> {
        let mask = (1u64 << self.metadata.bucket_bits) - 1;
        let bucket = (hash & mask) as usize;
        let (start, count) = self.bucket_ranges[bucket];
        let mut low = start;
        let mut high = start + count;
        while low < high {
            let middle = low + (high - low) / 2;
            let record = match self.record_at(middle) {
                Ok(record) => record,
                Err(_) => {
                    self.invalid_read.store(true, Ordering::Release);
                    return None;
                }
            };
            if record.hash < hash {
                low = middle + 1;
            } else if record.hash > hash {
                high = middle;
            } else {
                return Some(record.count);
            }
        }
        None
    }

    pub fn ensure_valid(&self) -> io::Result<()> {
        if self.invalid_read.load(Ordering::Acquire) {
            Err(invalid("global occurrence policy positional read failed"))
        } else {
            Ok(())
        }
    }
}

impl super::seed::OccurrencePolicy for GlobalOccurrencePolicy {
    fn global_count(&self, hash: u64) -> Option<usize> {
        match self.lookup(hash) {
            Some(count) => match usize::try_from(count) {
                Ok(count) => Some(count),
                Err(_) => {
                    self.invalid_read.store(true, Ordering::Release);
                    None
                }
            },
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path(suffix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rammap-global-policy-{}-{nonce}-{suffix}",
            std::process::id()
        ))
    }

    fn metadata() -> GlobalOccurrencePolicyMetadata {
        GlobalOccurrencePolicyMetadata {
            bucket_bits: 4,
            shard_count: 2,
            parameter_digest: [1; 32],
            target_digest: [2; 32],
        }
    }

    #[test]
    fn round_trip_supports_positional_global_lookup() {
        let path = test_path("round-trip");
        let mut writer = GlobalOccurrencePolicyWriter::create(&path, metadata()).unwrap();
        writer
            .write_record(GlobalOccurrenceRecord {
                bucket: 1,
                hash: 0x21,
                count: 3,
            })
            .unwrap();
        writer
            .write_record(GlobalOccurrenceRecord {
                bucket: 2,
                hash: 0x32,
                count: 9,
            })
            .unwrap();
        let facts = writer.finish().unwrap();
        let policy = GlobalOccurrencePolicy::open(&path, &metadata()).unwrap();
        assert_eq!(policy.facts(), facts);
        assert_eq!(policy.lookup(0x21), Some(3));
        assert_eq!(policy.lookup(0x32), Some(9));
        assert_eq!(policy.lookup(0x43), None);
        policy.ensure_valid().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn corruption_and_truncation_fail_closed() {
        let path = test_path("corruption");
        let mut writer = GlobalOccurrencePolicyWriter::create(&path, metadata()).unwrap();
        writer
            .write_record(GlobalOccurrenceRecord {
                bucket: 1,
                hash: 0x21,
                count: 3,
            })
            .unwrap();
        writer.finish().unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[16] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(GlobalOccurrencePolicy::open(&path, &metadata()).is_err());
        fs::remove_file(&path).unwrap();

        let mut writer = GlobalOccurrencePolicyWriter::create(&path, metadata()).unwrap();
        writer
            .write_record(GlobalOccurrenceRecord {
                bucket: 1,
                hash: 0x21,
                count: 3,
            })
            .unwrap();
        writer.finish().unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.pop();
        fs::write(&path, bytes).unwrap();
        assert!(GlobalOccurrencePolicy::open(&path, &metadata()).is_err());
        fs::remove_file(path).unwrap();
    }
}
