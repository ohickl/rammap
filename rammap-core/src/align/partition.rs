//! Exact, native single-end partition orchestration.
//!
//! A shard produces pre-finalization candidates into a versioned raw spool.
//! The merge pass adjusts shard-local target identifiers and invokes the same
//! query-global finalizer used by the monolithic path. Python is not involved
//! in this transaction and no catalog-sized candidate collection is retained.

use super::extend::AlignmentContext;
use super::index::{Index, TargetSequence};
use super::map::{map_query, MapContext, MapOptions};
use super::occurrence_sidecar::{
    OccurrenceRecord, OccurrenceSidecarMetadata, OccurrenceSidecarReader, OccurrenceSidecarWriter,
};
use super::pipeline::{
    align_query_raw, finalize_raw_query, format_output, MapResult, OutputConfig, RawQuery, ReadInfo,
};
use super::raw_spool::{RawSpoolMetadata, RawSpoolReader, RawSpoolWriter};
use crate::fasta;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

const MAX_CALIBRATION_BINS: usize = 16 * 1024 * 1024;
const PARTITION_MANIFEST_MAGIC: &[u8; 4] = b"RXPM";
const PARTITION_MANIFEST_VERSION: u32 = 1;
const STAGE_INIT: u8 = 0;
const STAGE_SIDECARS: u8 = 1;
const STAGE_RAW: u8 = 2;
const STAGE_OUTPUT_READY: u8 = 3;
const STAGE_COMPLETE: u8 = 4;
const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

/// Inputs and immutable parameters for one native partitioned run.
pub struct PartitionedMapConfig {
    pub target_paths: Vec<PathBuf>,
    pub query_path: PathBuf,
    pub output_path: PathBuf,
    pub spool_dir: PathBuf,
    pub k: usize,
    pub w: usize,
    pub is_hpc: bool,
    pub index_max_occ: usize,
    pub mid_occ_frac: f32,
    pub options: MapOptions,
    pub output: OutputConfig,
    pub parameter_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub query_digest: [u8; 32],
    pub resume: bool,
}

/// Durable-output facts returned by a completed partitioned operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionedMapReceipt {
    pub shard_count: u32,
    pub query_count: u64,
    pub mid_occ: usize,
    pub output_bytes: u64,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn checksum_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= byte as u64;
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn occurrence_metadata(
    config: &PartitionedMapConfig,
    shard_id: u32,
    shard_count: u32,
) -> OccurrenceSidecarMetadata {
    OccurrenceSidecarMetadata {
        bucket_bits: 10u32.min((2 * config.k) as u32),
        shard_id,
        shard_count,
        parameter_digest: config.parameter_digest,
        target_digest: config.target_digest,
    }
}

fn raw_metadata(
    config: &PartitionedMapConfig,
    shard_id: u32,
    shard_count: u32,
) -> RawSpoolMetadata {
    RawSpoolMetadata {
        shard_id,
        shard_count,
        parameter_digest: config.parameter_digest,
        target_digest: config.target_digest,
        query_digest: config.query_digest,
    }
}

fn sidecar_path(config: &PartitionedMapConfig, shard_id: u32) -> PathBuf {
    config
        .spool_dir
        .join(format!("occurrence-{shard_id:08}.rxoc"))
}

fn raw_path(config: &PartitionedMapConfig, shard_id: u32) -> PathBuf {
    config.spool_dir.join(format!("raw-{shard_id:08}.rxrs"))
}

fn partial_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.partial", path.display()))
}

fn manifest_path(config: &PartitionedMapConfig) -> PathBuf {
    config.spool_dir.join("partitioned.manifest")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PartitionManifest {
    shard_count: u32,
    parameter_digest: [u8; 32],
    target_digest: [u8; 32],
    query_digest: [u8; 32],
    stage: u8,
    mid_occ: u64,
    query_count: u64,
    completed_raw: u32,
    output_bytes: u64,
    output_checksum: u64,
}

impl PartitionManifest {
    fn initial(config: &PartitionedMapConfig, shard_count: u32) -> Self {
        Self {
            shard_count,
            parameter_digest: config.parameter_digest,
            target_digest: config.target_digest,
            query_digest: config.query_digest,
            stage: STAGE_INIT,
            mid_occ: 0,
            query_count: 0,
            completed_raw: 0,
            output_bytes: 0,
            output_checksum: 0,
        }
    }

    fn validate_config(&self, config: &PartitionedMapConfig, shard_count: u32) -> io::Result<()> {
        if self.shard_count != shard_count
            || self.parameter_digest != config.parameter_digest
            || self.target_digest != config.target_digest
            || self.query_digest != config.query_digest
        {
            return Err(invalid("partitioned resume manifest identity mismatch"));
        }
        if self.stage > STAGE_COMPLETE || self.completed_raw > shard_count {
            return Err(invalid("partitioned resume manifest stage is invalid"));
        }
        if self.stage >= STAGE_SIDECARS && self.mid_occ == 0 {
            return Err(invalid("partitioned resume manifest has no mid_occ"));
        }
        if self.stage >= STAGE_RAW && self.completed_raw != shard_count {
            return Err(invalid("partitioned resume manifest raw stage is incomplete"));
        }
        if self.stage >= STAGE_OUTPUT_READY && self.output_checksum == 0 {
            return Err(invalid("partitioned resume manifest output facts are invalid"));
        }
        Ok(())
    }
}

fn encode_manifest(manifest: PartitionManifest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(PARTITION_MANIFEST_MAGIC);
    bytes.extend_from_slice(&PARTITION_MANIFEST_VERSION.to_le_bytes());
    bytes.extend_from_slice(&manifest.shard_count.to_le_bytes());
    bytes.push(manifest.stage);
    bytes.extend_from_slice(&manifest.parameter_digest);
    bytes.extend_from_slice(&manifest.target_digest);
    bytes.extend_from_slice(&manifest.query_digest);
    bytes.extend_from_slice(&manifest.mid_occ.to_le_bytes());
    bytes.extend_from_slice(&manifest.query_count.to_le_bytes());
    bytes.extend_from_slice(&manifest.completed_raw.to_le_bytes());
    bytes.extend_from_slice(&manifest.output_bytes.to_le_bytes());
    bytes.extend_from_slice(&manifest.output_checksum.to_le_bytes());
    let checksum = checksum_update(FNV_OFFSET, &bytes);
    bytes.extend_from_slice(&checksum.to_le_bytes());
    bytes
}

fn take_bytes<'a>(bytes: &'a [u8], offset: &mut usize, count: usize) -> io::Result<&'a [u8]> {
    let end = offset
        .checked_add(count)
        .ok_or_else(|| invalid("partitioned manifest length overflow"))?;
    if end > bytes.len() {
        return Err(invalid("partitioned resume manifest is truncated"));
    }
    let value = &bytes[*offset..end];
    *offset = end;
    Ok(value)
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(take_bytes(bytes, offset, 4)?.try_into().unwrap()))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(take_bytes(bytes, offset, 8)?.try_into().unwrap()))
}

fn load_manifest(path: &Path) -> io::Result<PartitionManifest> {
    let bytes = fs::read(path)?;
    if bytes.len() < 8 || &bytes[..4] != PARTITION_MANIFEST_MAGIC {
        return Err(invalid("partitioned resume manifest magic is invalid"));
    }
    let expected_checksum = u64::from_le_bytes(
        bytes[bytes.len() - 8..]
            .try_into()
            .map_err(|_| invalid("partitioned resume manifest checksum is truncated"))?,
    );
    if checksum_update(FNV_OFFSET, &bytes[..bytes.len() - 8]) != expected_checksum {
        return Err(invalid("partitioned resume manifest checksum mismatch"));
    }
    let mut offset = 4;
    if take_u32(&bytes, &mut offset)? != PARTITION_MANIFEST_VERSION {
        return Err(invalid("partitioned resume manifest version is unsupported"));
    }
    let shard_count = take_u32(&bytes, &mut offset)?;
    let stage = take_bytes(&bytes, &mut offset, 1)?[0];
    let parameter_digest = take_bytes(&bytes, &mut offset, 32)?.try_into().unwrap();
    let target_digest = take_bytes(&bytes, &mut offset, 32)?.try_into().unwrap();
    let query_digest = take_bytes(&bytes, &mut offset, 32)?.try_into().unwrap();
    let mid_occ = take_u64(&bytes, &mut offset)?;
    let query_count = take_u64(&bytes, &mut offset)?;
    let completed_raw = take_u32(&bytes, &mut offset)?;
    let output_bytes = take_u64(&bytes, &mut offset)?;
    let output_checksum = take_u64(&bytes, &mut offset)?;
    if offset != bytes.len() - 8 {
        return Err(invalid("partitioned resume manifest has trailing fields"));
    }
    Ok(PartitionManifest {
        shard_count,
        parameter_digest,
        target_digest,
        query_digest,
        stage,
        mid_occ,
        query_count,
        completed_raw,
        output_bytes,
        output_checksum,
    })
}

fn write_manifest(path: &Path, manifest: PartitionManifest) -> io::Result<()> {
    let temporary = partial_path(path);
    if temporary.exists() {
        return Err(invalid("partitioned resume manifest has an uncommitted temporary file"));
    }
    let mut file = create_new(&temporary)?;
    file.write_all(&encode_manifest(manifest))?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn validate_config(config: &PartitionedMapConfig) -> io::Result<()> {
    if config.target_paths.is_empty() {
        return Err(invalid(
            "partitioned mapping requires at least one target shard",
        ));
    }
    if config.k == 0 || config.w == 0 {
        return Err(invalid("partitioned mapping requires positive k and w"));
    }
    if !(0.0..1.0).contains(&config.mid_occ_frac) {
        return Err(invalid("mid_occ_frac must be in [0, 1)"));
    }
    let max_mid = config.options.seeding.max_mid_occ.max(1) as usize;
    let histogram_max = config.index_max_occ.min(max_mid);
    if histogram_max == usize::MAX || histogram_max > MAX_CALIBRATION_BINS {
        return Err(invalid(format!(
            "occurrence calibration bound {} exceeds the fixed-width limit {}",
            histogram_max, MAX_CALIBRATION_BINS
        )));
    }
    Ok(())
}

fn build_occurrence_sidecars(
    config: &PartitionedMapConfig,
) -> io::Result<(Vec<TargetSequence>, Vec<usize>)> {
    let shard_count =
        u32::try_from(config.target_paths.len()).map_err(|_| invalid("too many target shards"))?;
    let mut all_seqs = Vec::new();
    let mut offsets = Vec::with_capacity(config.target_paths.len());
    let mut next_ref_id = 0usize;
    let mut next_offset = 0u64;

    for (shard_id, target_path) in config.target_paths.iter().enumerate() {
        let sidecar = sidecar_path(config, shard_id as u32);
        if sidecar.exists() {
            return Err(invalid("partitioned occurrence sidecar exists before its manifest stage"));
        }
        let temporary = partial_path(&sidecar);
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        let file = create_new(&temporary)?;
        let mut writer = OccurrenceSidecarWriter::new(
            BufWriter::new(file),
            occurrence_metadata(config, shard_id as u32, shard_count),
        )?;
        let mut sidecar_error = None;
        let index = Index::build_fasta_with_occurrence_counts(
            target_path
                .to_str()
                .ok_or_else(|| invalid("target path is not UTF-8"))?,
            config.w,
            config.k,
            config.is_hpc,
            config.index_max_occ,
            |bucket, hash, count| {
                if sidecar_error.is_none() {
                    if let Err(error) = writer.write_record(OccurrenceRecord {
                        bucket,
                        hash,
                        count,
                    }) {
                        sidecar_error = Some(error);
                    }
                }
            },
        )?;
        if let Some(error) = sidecar_error {
            return Err(error);
        }
        let buffered = writer.finish()?;
        buffered
            .into_inner()
            .map_err(|error| io::Error::other(error.to_string()))?
            .sync_all()?;
        fs::rename(temporary, sidecar)?;

        offsets.push(next_ref_id);
        for mut seq in index.seqs.iter().cloned() {
            seq.offset = seq
                .offset
                .checked_add(next_offset)
                .ok_or_else(|| invalid("target offset overflow"))?;
            all_seqs.push(seq);
            next_ref_id = next_ref_id
                .checked_add(1)
                .ok_or_else(|| invalid("target identifier overflow"))?;
        }
        next_offset = next_offset
            .checked_add(index.seqs.iter().map(|s| s.len as u64).sum())
            .ok_or_else(|| invalid("target length overflow"))?;
    }
    Ok((all_seqs, offsets))
}

fn read_target_metadata(config: &PartitionedMapConfig) -> io::Result<(Vec<TargetSequence>, Vec<usize>)> {
    let mut all_seqs = Vec::new();
    let mut offsets = Vec::with_capacity(config.target_paths.len());
    let mut next_ref_id = 0usize;
    let mut next_offset = 0u64;
    for target_path in &config.target_paths {
        let mut reader = fasta::open(
            target_path
                .to_str()
                .ok_or_else(|| invalid("target path is not UTF-8"))?,
        )?;
        offsets.push(next_ref_id);
        while let Some(record) = reader.read_next().map_err(io::Error::other)? {
            let name = record
                .name()
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            let len = record.sequence().len();
            all_seqs.push(TargetSequence {
                name,
                len,
                offset: next_offset,
                is_alt: false,
            });
            next_ref_id = next_ref_id
                .checked_add(1)
                .ok_or_else(|| invalid("target identifier overflow"))?;
            next_offset = next_offset
                .checked_add(len as u64)
                .ok_or_else(|| invalid("target offset overflow"))?;
        }
    }
    Ok((all_seqs, offsets))
}

fn validate_sidecars(config: &PartitionedMapConfig, shard_count: u32) -> io::Result<()> {
    for shard_id in 0..shard_count {
        let file = File::open(sidecar_path(config, shard_id))?;
        let expected = occurrence_metadata(config, shard_id, shard_count);
        OccurrenceSidecarReader::new(BufReader::new(file), Some(&expected))?.finish()?;
    }
    Ok(())
}

fn validate_raw_spool(
    config: &PartitionedMapConfig,
    shard_id: u32,
    shard_count: u32,
) -> io::Result<u64> {
    let file = File::open(raw_path(config, shard_id))?;
    let expected = raw_metadata(config, shard_id, shard_count);
    let mut reader = RawSpoolReader::new(BufReader::new(file))?;
    reader.validate_metadata(&expected)?;
    let mut count = 0u64;
    while reader.next_query()?.is_some() {
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("raw spool query count overflow"))?;
    }
    Ok(count)
}

fn output_stats(path: &Path) -> io::Result<(u64, u64)> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 1024 * 1024];
    let mut length = 0u64;
    let mut checksum = FNV_OFFSET;
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or_else(|| invalid("partitioned output length overflow"))?;
        checksum = checksum_update(checksum, &bytes[..count]);
    }
    Ok((length, checksum))
}

fn calibrated_mid_occ(config: &PartitionedMapConfig, sidecar_count: u32) -> io::Result<usize> {
    let max_mid = config.options.seeding.max_mid_occ.max(1) as usize;
    let histogram_max = config.index_max_occ.min(max_mid);
    let mut histogram = vec![0u64; histogram_max + 1];
    let mut readers = Vec::with_capacity(sidecar_count as usize);
    for shard_id in 0..sidecar_count {
        let path = sidecar_path(config, shard_id);
        let file = File::open(path)?;
        let expected = occurrence_metadata(config, shard_id, sidecar_count);
        readers.push(OccurrenceSidecarReader::new(
            BufReader::new(file),
            Some(&expected),
        )?);
    }

    let mut heap: BinaryHeap<Reverse<(u32, u64, usize, u32)>> = BinaryHeap::new();
    for (shard, reader) in readers.iter_mut().enumerate() {
        if let Some(record) = reader.next_record()? {
            heap.push(Reverse((record.bucket, record.hash, shard, record.count)));
        }
    }

    while let Some(Reverse((bucket, hash, shard, count))) = heap.pop() {
        let mut total = u64::from(count);
        if let Some(record) = readers[shard].next_record()? {
            heap.push(Reverse((record.bucket, record.hash, shard, record.count)));
        }
        while let Some(Reverse((next_bucket, next_hash, next_shard, next_count))) =
            heap.peek().copied()
        {
            if (next_bucket, next_hash) != (bucket, hash) {
                break;
            }
            heap.pop();
            total = total
                .checked_add(u64::from(next_count))
                .ok_or_else(|| invalid("global occurrence count overflow"))?;
            if let Some(record) = readers[next_shard].next_record()? {
                heap.push(Reverse((
                    record.bucket,
                    record.hash,
                    next_shard,
                    record.count,
                )));
            }
        }
        if config.index_max_occ == usize::MAX || total <= config.index_max_occ as u64 {
            let bin = (total as usize).min(histogram_max);
            histogram[bin] = histogram[bin]
                .checked_add(1)
                .ok_or_else(|| invalid("occurrence histogram overflow"))?;
        }
    }

    if config.mid_occ_frac <= 0.0 {
        return Ok(usize::MAX);
    }
    let retained = histogram.iter().sum::<u64>();
    if retained == 0 {
        return Ok(config.options.seeding.min_mid_occ.max(1) as usize);
    }
    let rank = (((1.0f64 - config.mid_occ_frac as f64) * retained as f64) as u64).min(retained - 1);
    let mut seen = 0u64;
    let mut count_at_rank = histogram_max;
    for (count, frequency) in histogram.iter().enumerate() {
        if rank < seen + *frequency {
            count_at_rank = count;
            break;
        }
        seen += *frequency;
    }
    let mut threshold = count_at_rank.saturating_add(1);
    let min_mid = config.options.seeding.min_mid_occ.max(1) as usize;
    threshold = threshold.max(min_mid);
    if config.options.seeding.max_mid_occ > config.options.seeding.min_mid_occ {
        threshold = threshold.min(max_mid);
    }
    Ok(threshold)
}

fn map_shard_to_raw(
    config: &PartitionedMapConfig,
    shard_id: u32,
    shard_count: u32,
    mid_occ: usize,
) -> io::Result<u64> {
    let target_path = config.target_paths[shard_id as usize]
        .to_str()
        .ok_or_else(|| invalid("target path is not UTF-8"))?;
    let index = Index::build_fasta(
        target_path,
        config.w,
        config.k,
        config.is_hpc,
        config.index_max_occ,
    )?;
    let mut options = config.options.clone();
    options.seeding.mid_occ = mid_occ;
    super::super::api::finalize_options(&mut options, config.k);
    let raw = raw_path(config, shard_id);
    if raw.exists() {
        return Err(invalid("partitioned raw spool exists before its manifest stage"));
    }
    let temporary = partial_path(&raw);
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    let file = create_new(&temporary)?;
    let mut writer = RawSpoolWriter::new(
        BufWriter::new(file),
        raw_metadata(config, shard_id, shard_count),
    )?;
    let mut reader = fasta::open(
        config
            .query_path
            .to_str()
            .ok_or_else(|| invalid("query path is not UTF-8"))?,
    )?;
    let mut map_ctx = MapContext::new();
    let mut align_ctx = AlignmentContext::new();
    let mut ordinal = 0u64;
    while let Some(record) = reader.read_next().map_err(io::Error::other)? {
        let raw = if options.filtering.max_qlen > 0
            && record.sequence().len() > options.filtering.max_qlen as usize
        {
            RawQuery {
                results: Vec::new(),
                recalc_infos: Vec::new(),
                rep_len: 0,
                stats: Default::default(),
            }
        } else {
            let (regs, rep_len, stats, squeezed) = map_query(
                &options,
                &index,
                record.name(),
                record.sequence(),
                &mut map_ctx,
            );
            align_query_raw(
                &options,
                &index,
                record.sequence(),
                &mut align_ctx,
                &mut map_ctx,
                None,
                &config.output,
                MapResult {
                    regs,
                    rep_len,
                    stats,
                    squeezed,
                },
            )
        };
        writer.write_query(ordinal, 0, record.sequence().len() as u64, &raw)?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| invalid("query ordinal overflow"))?;
    }
    let buffered = writer.finish()?;
    buffered
        .into_inner()
        .map_err(|error| io::Error::other(error.to_string()))?
        .sync_all()?;
    fs::rename(temporary, raw)?;
    Ok(ordinal)
}

fn merge_to_partial(
    config: &PartitionedMapConfig,
    all_seqs: Vec<TargetSequence>,
    ref_offsets: &[usize],
    shard_count: u32,
    mid_occ: usize,
) -> io::Result<(u64, u64, u64)> {
    let mut readers = Vec::with_capacity(shard_count as usize);
    for shard_id in 0..shard_count {
        let file = File::open(raw_path(config, shard_id))?;
        let expected = raw_metadata(config, shard_id, shard_count);
        readers.push(RawSpoolReader::new(BufReader::new(file))?);
        readers.last().unwrap().validate_metadata(&expected)?;
    }
    let global_index = Index::header_only(config.k, config.w, config.is_hpc, all_seqs);
    let mut options = config.options.clone();
    options.seeding.mid_occ = mid_occ;
    super::super::api::finalize_options(&mut options, config.k);
    let partial = PathBuf::from(format!("{}.partial", config.output_path.display()));
    let file = create_new(&partial)?;
    let mut output = BufWriter::new(file);
    let mut query_reader = fasta::open(
        config
            .query_path
            .to_str()
            .ok_or_else(|| invalid("query path is not UTF-8"))?,
    )?;
    let mut query_count = 0u64;
    while let Some(record) = query_reader.read_next().map_err(io::Error::other)? {
        let mut merged = RawQuery {
            results: Vec::new(),
            recalc_infos: Vec::new(),
            rep_len: 0,
            stats: Default::default(),
        };
        for (shard, reader) in readers.iter_mut().enumerate() {
            let frame = reader
                .next_query()?
                .ok_or_else(|| invalid("raw spool ended before the query stream"))?;
            if frame.ordinal != query_count
                || frame.segment != 0
                || frame.qlen != record.sequence().len() as u64
            {
                return Err(invalid(
                    "raw spool query identity does not match the query stream",
                ));
            }
            merged.rep_len = merged
                .rep_len
                .checked_add(frame.raw.rep_len)
                .ok_or_else(|| invalid("merged repetitive length overflow"))?;
            for mut result in frame.raw.results {
                result.ref_id = result
                    .ref_id
                    .checked_add(ref_offsets[shard])
                    .ok_or_else(|| invalid("merged target identifier overflow"))?;
                merged.results.push(result);
            }
            merged.recalc_infos.extend(frame.raw.recalc_infos);
        }
        let processed = finalize_raw_query(
            merged,
            &options,
            &global_index,
            &config.output,
            record.sequence().len(),
        );
        let qual = match record.quality() {
            Some(bytes) => Some(
                std::str::from_utf8(bytes).map_err(|_| invalid("query quality is not UTF-8"))?,
            ),
            None => None,
        };
        let read = ReadInfo {
            qname: record.name(),
            qseq: record.sequence(),
            qual,
            comment: record.description(),
            n_seg: 1,
            seg_idx: 0,
        };
        let mut rendered = String::new();
        format_output(
            &mut rendered,
            &options,
            &global_index,
            &read,
            &processed,
            &config.output,
            None,
        );
        output.write_all(rendered.as_bytes())?;
        query_count = query_count
            .checked_add(1)
            .ok_or_else(|| invalid("query count overflow"))?;
    }
    for reader in readers.iter_mut() {
        if reader.next_query()?.is_some() {
            return Err(invalid(
                "raw spool contains queries absent from the query stream",
            ));
        }
    }
    output.flush()?;
    let file = output
        .into_inner()
        .map_err(|error| io::Error::other(error.to_string()))?;
    file.sync_all()?;
    let (output_bytes, output_checksum) = output_stats(&partial)?;
    Ok((query_count, output_bytes, output_checksum))
}

fn publish_partial_output(config: &PartitionedMapConfig, expected: (u64, u64)) -> io::Result<()> {
    if config.output_path.exists() {
        return Err(invalid("refusing to replace an existing partitioned output"));
    }
    let temporary = partial_path(&config.output_path);
    if output_stats(&temporary)? != expected {
        return Err(invalid("partitioned temporary output facts do not match the manifest"));
    }
    fs::rename(temporary, &config.output_path)?;
    Ok(())
}

/// Build occurrence sidecars, map each target shard once, and globally
/// finalize/publish one deterministic single-end PAF/SAM output.
pub fn map_partitioned_fasta_to_paf(
    config: &PartitionedMapConfig,
) -> io::Result<PartitionedMapReceipt> {
    validate_config(config)?;
    fs::create_dir_all(&config.spool_dir)?;
    let shard_count =
        u32::try_from(config.target_paths.len()).map_err(|_| invalid("too many target shards"))?;
    let manifest_file = manifest_path(config);
    let mut manifest = if config.resume {
        if partial_path(&manifest_file).exists() {
            return Err(invalid("partitioned resume manifest has an uncommitted temporary file"));
        }
        let manifest = load_manifest(&manifest_file)?;
        manifest.validate_config(config, shard_count)?;
        manifest
    } else {
        if manifest_file.exists()
            || config.output_path.exists()
            || partial_path(&config.output_path).exists()
        {
            return Err(invalid(
                "partitioned mapping artifacts already exist; use resume to reopen them",
            ));
        }
        let manifest = PartitionManifest::initial(config, shard_count);
        write_manifest(&manifest_file, manifest)?;
        manifest
    };

    if manifest.stage == STAGE_COMPLETE {
        let observed = output_stats(&config.output_path)?;
        if observed != (manifest.output_bytes, manifest.output_checksum) {
            return Err(invalid("completed partitioned output does not match its manifest"));
        }
        return Ok(PartitionedMapReceipt {
            shard_count,
            query_count: manifest.query_count,
            mid_occ: manifest.mid_occ as usize,
            output_bytes: manifest.output_bytes,
        });
    }

    if manifest.stage == STAGE_OUTPUT_READY {
        let expected = (manifest.output_bytes, manifest.output_checksum);
        if config.output_path.exists() {
            if output_stats(&config.output_path)? != expected {
                return Err(invalid("published partitioned output does not match its manifest"));
            }
        } else {
            publish_partial_output(config, expected)?;
        }
        manifest.stage = STAGE_COMPLETE;
        write_manifest(&manifest_file, manifest)?;
        return Ok(PartitionedMapReceipt {
            shard_count,
            query_count: manifest.query_count,
            mid_occ: manifest.mid_occ as usize,
            output_bytes: manifest.output_bytes,
        });
    }

    let (all_seqs, ref_offsets) = if manifest.stage >= STAGE_SIDECARS {
        validate_sidecars(config, shard_count)?;
        read_target_metadata(config)?
    } else {
        let metadata = build_occurrence_sidecars(config)?;
        let mid_occ = calibrated_mid_occ(config, shard_count)?;
        manifest.stage = STAGE_SIDECARS;
        manifest.mid_occ = mid_occ as u64;
        write_manifest(&manifest_file, manifest)?;
        metadata
    };
    let mid_occ = usize::try_from(manifest.mid_occ)
        .map_err(|_| invalid("partitioned resume mid_occ exceeds usize"))?;
    let mut expected_queries = None;
    for shard_id in 0..shard_count {
        let query_count = if shard_id < manifest.completed_raw {
            validate_raw_spool(config, shard_id, shard_count)?
        } else if raw_path(config, shard_id).exists() {
            // The raw spool may have been atomically committed immediately
            // before a manifest update was interrupted. Validate it and
            // advance the manifest rather than rebuilding an immutable stage.
            validate_raw_spool(config, shard_id, shard_count)?
        } else {
            let query_count = map_shard_to_raw(config, shard_id, shard_count, mid_occ)?;
            manifest.completed_raw = shard_id + 1;
            manifest.query_count = query_count;
            if manifest.completed_raw == shard_count {
                manifest.stage = STAGE_RAW;
            }
            write_manifest(&manifest_file, manifest)?;
            query_count
        };
        if let Some(expected) = expected_queries {
            if expected != query_count {
                return Err(invalid("shards observed different query counts"));
            }
        } else {
            expected_queries = Some(query_count);
        }
    }
    if manifest.stage != STAGE_RAW {
        return Err(invalid("partitioned raw stage did not complete"));
    }
    if config.output_path.exists() {
        return Err(invalid("partitioned output exists before publication stage"));
    }
    let temporary_output = partial_path(&config.output_path);
    if temporary_output.exists() {
        if !config.resume {
            return Err(invalid("partitioned output has an uncommitted temporary file"));
        }
        fs::remove_file(&temporary_output)?;
    }
    let (query_count, output_bytes, output_checksum) =
        merge_to_partial(config, all_seqs, &ref_offsets, shard_count, mid_occ)?;
    manifest.stage = STAGE_OUTPUT_READY;
    manifest.query_count = query_count;
    manifest.output_bytes = output_bytes;
    manifest.output_checksum = output_checksum;
    write_manifest(&manifest_file, manifest)?;
    publish_partial_output(config, (output_bytes, output_checksum))?;
    manifest.stage = STAGE_COMPLETE;
    write_manifest(&manifest_file, manifest)?;
    Ok(PartitionedMapReceipt {
        shard_count,
        query_count,
        mid_occ,
        output_bytes,
    })
}

/// Compatibility name for callers that do not distinguish PAF/SAM output at
/// the orchestration boundary. The output schema is selected by
/// [`PartitionedMapConfig::output`].
pub fn map_partitioned_fasta_to_output(
    config: &PartitionedMapConfig,
) -> io::Result<PartitionedMapReceipt> {
    map_partitioned_fasta_to_paf(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::pipeline::{align_and_format_query, ReadInfo};
    use crate::api::{apply_preset_str, finalize_options};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rammap-partition-test-{}-{nonce}",
            std::process::id()
        ))
    }

    fn output_config() -> OutputConfig {
        OutputConfig {
            do_cigar: true,
            do_cs: false,
            cs_long: false,
            do_md: false,
            do_ds: false,
            eqx: false,
            output_sam: false,
            rg_id: None,
            split_mode: false,
        }
    }

    #[test]
    fn partitioned_single_end_matches_monolithic_output() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let shard_a = root.join("a.fa");
        let shard_b = root.join("b.fa");
        let query = root.join("queries.fq");
        fs::write(
            &shard_a,
            b">target_a\nACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT\n",
        )
        .unwrap();
        fs::write(
            &shard_b,
            b">target_b\nTTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGG\n",
        )
        .unwrap();
        fs::write(
            &query,
            b"@read_a comment\nACGTACGTACGTACGTACGTACGTACGTACGT\n+\nIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n@read_b\nTTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGG\n+\nIIIIIIIIIIIIIIIIIIIIIIII\n",
        )
        .unwrap();

        let k = 5;
        let w = 3;
        let index_max_occ = 1000;
        let mid_occ_frac = 2e-4;
        let mut options = MapOptions::default();
        let mut preset_k = k;
        let mut preset_w = w;
        let mut is_hpc = false;
        apply_preset_str(
            &mut options,
            &mut preset_k,
            &mut preset_w,
            &mut is_hpc,
            "map-ont",
        )
        .unwrap();
        options.seeding.min_mid_occ = 1;
        options.seeding.max_mid_occ = 1000;
        finalize_options(&mut options, k);
        let global_index = Index::build(
            vec![
                (
                    "target_a".to_string(),
                    b"ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT".to_vec(),
                ),
                (
                    "target_b".to_string(),
                    b"TTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGGTTTTCCCCAAAAGGGG".to_vec(),
                ),
            ],
            w,
            k,
            is_hpc,
            index_max_occ,
        );
        options.seeding.mid_occ = global_index.cal_mid_occ(
            mid_occ_frac,
            options.seeding.min_mid_occ,
            options.seeding.max_mid_occ,
        );
        let out_cfg = output_config();
        let mut monolithic = String::new();
        let mut reader = fasta::open(query.to_str().unwrap()).unwrap();
        let mut align_ctx = AlignmentContext::new();
        let mut map_ctx = MapContext::new();
        while let Some(record) = reader.read_next().unwrap() {
            let read = ReadInfo {
                qname: record.name(),
                qseq: record.sequence(),
                qual: Some(std::str::from_utf8(record.quality().unwrap()).unwrap()),
                comment: record.description(),
                n_seg: 1,
                seg_idx: 0,
            };
            let (rendered, _) = align_and_format_query(
                &options,
                &global_index,
                &read,
                &mut align_ctx,
                &mut map_ctx,
                None,
                None,
                &out_cfg,
            );
            monolithic.push_str(&rendered);
        }

        let output = root.join("partitioned.paf");
        let config = PartitionedMapConfig {
            target_paths: vec![shard_a, shard_b],
            query_path: query,
            output_path: output.clone(),
            spool_dir: root.join("spools"),
            k,
            w,
            is_hpc,
            index_max_occ,
            mid_occ_frac,
            options,
            output: out_cfg,
            parameter_digest: [1; 32],
            target_digest: [2; 32],
            query_digest: [3; 32],
            resume: false,
        };
        let receipt = map_partitioned_fasta_to_output(&config).unwrap();
        assert_eq!(receipt.query_count, 2);
        let fresh_output = std::fs::read_to_string(&output).unwrap();
        assert_eq!(fresh_output, monolithic);
        assert!(config.spool_dir.join("raw-00000000.rxrs").is_file());
        assert!(config.spool_dir.join("occurrence-00000001.rxoc").is_file());

        // Reopen at the publication boundary: the output is durable as a
        // temporary artifact and the manifest records the exact bytes before
        // the final rename. Resume must publish the same bytes.
        fs::rename(&output, partial_path(&output)).unwrap();
        let mut resume_manifest = load_manifest(&manifest_path(&config)).unwrap();
        resume_manifest.stage = STAGE_OUTPUT_READY;
        write_manifest(&manifest_path(&config), resume_manifest).unwrap();
        let mut resumed = config;
        resumed.resume = true;
        let resumed_receipt = map_partitioned_fasta_to_output(&resumed).unwrap();
        assert_eq!(resumed_receipt, receipt);
        assert_eq!(std::fs::read_to_string(output).unwrap(), fresh_output);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partitioned_resume_rejects_manifest_corruption() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target.fa");
        let query = root.join("query.fa");
        fs::write(&target, b">target\nACGTACGTACGTACGTACGTACGT\n").unwrap();
        fs::write(&query, b">query\nACGTACGTACGT\n").unwrap();
        let mut options = MapOptions::default();
        let mut config = PartitionedMapConfig {
            target_paths: vec![target],
            query_path: query,
            output_path: root.join("output.paf"),
            spool_dir: root.join("spool"),
            k: 5,
            w: 3,
            is_hpc: false,
            index_max_occ: 100,
            mid_occ_frac: 2e-4,
            options: {
                finalize_options(&mut options, 5);
                options
            },
            output: output_config(),
            parameter_digest: [4; 32],
            target_digest: [5; 32],
            query_digest: [6; 32],
            resume: false,
        };
        let _ = map_partitioned_fasta_to_output(&config).unwrap();
        let manifest = manifest_path(&config);
        let mut bytes = fs::read(&manifest).unwrap();
        bytes[20] ^= 1;
        fs::write(manifest, bytes).unwrap();
        config.resume = true;
        assert!(map_partitioned_fasta_to_output(&config).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
