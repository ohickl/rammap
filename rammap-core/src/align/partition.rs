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
use std::io::{self, BufReader, BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};

const MAX_CALIBRATION_BINS: usize = 16 * 1024 * 1024;

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
        let file = create_new(&sidecar)?;
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
    let index = Index::build_fasta_with_occurrence_counts(
        target_path,
        config.w,
        config.k,
        config.is_hpc,
        config.index_max_occ,
        |_, _, _| {},
    )?;
    let mut options = config.options.clone();
    options.seeding.mid_occ = mid_occ;
    super::super::api::finalize_options(&mut options, config.k);
    let file = create_new(&raw_path(config, shard_id))?;
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
    Ok(ordinal)
}

fn merge_and_publish(
    config: &PartitionedMapConfig,
    all_seqs: Vec<TargetSequence>,
    ref_offsets: &[usize],
    shard_count: u32,
    mid_occ: usize,
) -> io::Result<u64> {
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
    if config.output_path.exists() {
        return Err(invalid(
            "refusing to replace an existing partitioned output",
        ));
    }
    fs::rename(&partial, &config.output_path)?;
    Ok(query_count)
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
    let (all_seqs, ref_offsets) = build_occurrence_sidecars(config)?;
    let mid_occ = calibrated_mid_occ(config, shard_count)?;
    let mut expected_queries = None;
    for shard_id in 0..shard_count {
        let query_count = map_shard_to_raw(config, shard_id, shard_count, mid_occ)?;
        if let Some(expected) = expected_queries {
            if expected != query_count {
                return Err(invalid("shards observed different query counts"));
            }
        } else {
            expected_queries = Some(query_count);
        }
    }
    let query_count = merge_and_publish(config, all_seqs, &ref_offsets, shard_count, mid_occ)?;
    let output_bytes = fs::metadata(&config.output_path)?.len();
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
        };
        let receipt = map_partitioned_fasta_to_output(&config).unwrap();
        assert_eq!(receipt.query_count, 2);
        assert_eq!(std::fs::read_to_string(output).unwrap(), monolithic);
        assert!(config.spool_dir.join("raw-00000000.rxrs").is_file());
        assert!(config.spool_dir.join("occurrence-00000001.rxoc").is_file());
        fs::remove_dir_all(root).unwrap();
    }
}
