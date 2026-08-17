//! Versioned native spool for pre-finalization alignment candidates.
//!
//! The format is intentionally independent of `bincode`. It is a bounded,
//! append-only interchange between shard mapping and query-global
//! finalization. Python never sees the records.

use super::pipeline::{AlnResult, DpRecalcInfo, RawQuery};
use std::io::{self, Cursor, ErrorKind, Read, Write};

const MAGIC: &[u8; 4] = b"RXRS";
const FRAME_MAGIC: &[u8; 4] = b"FRM1";
const TRAILER_MAGIC: &[u8; 4] = b"END1";
pub const RAW_SPOOL_VERSION: u32 = 1;
pub const RAW_SPOOL_MAX_FRAME_BYTES: u64 = 256 * 1024 * 1024;
const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

/// Immutable identity values that must match before a spool can be reused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSpoolMetadata {
    pub shard_id: u32,
    pub shard_count: u32,
    pub parameter_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub query_digest: [u8; 32],
}

#[derive(Debug)]
pub struct RawQueryFrame {
    pub ordinal: u64,
    pub segment: u8,
    pub qlen: u64,
    pub raw: RawQuery,
}

fn checksum_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= byte as u64;
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn write_all_checksum<W: Write>(writer: &mut W, checksum: &mut u64, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    *checksum = checksum_update(*checksum, bytes);
    Ok(())
}

fn put_u8(out: &mut Vec<u8>, value: u8) { out.push(value); }
fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_i32(out: &mut Vec<u8>, value: i32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_i64(out: &mut Vec<u8>, value: i64) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_f32(out: &mut Vec<u8>, value: f32) { put_u32(out, value.to_bits()); }
fn put_f64(out: &mut Vec<u8>, value: f64) { put_u64(out, value.to_bits()); }
fn put_bool(out: &mut Vec<u8>, value: bool) { put_u8(out, u8::from(value)); }

fn put_string(out: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| invalid("raw spool string is too long"))?;
    put_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn get_exact<'a>(cursor: &mut Cursor<&'a [u8]>, n: usize) -> io::Result<&'a [u8]> {
    let pos = cursor.position() as usize;
    let end = pos.checked_add(n).ok_or_else(|| invalid("raw spool length overflow"))?;
    if end > cursor.get_ref().len() {
        return Err(invalid("truncated raw spool frame"));
    }
    cursor.set_position(end as u64);
    Ok(&cursor.get_ref()[pos..end])
}

fn get_u8(cursor: &mut Cursor<&[u8]>) -> io::Result<u8> { Ok(get_exact(cursor, 1)?[0]) }
fn get_u32(cursor: &mut Cursor<&[u8]>) -> io::Result<u32> {
    Ok(u32::from_le_bytes(get_exact(cursor, 4)?.try_into().unwrap()))
}
fn get_i32(cursor: &mut Cursor<&[u8]>) -> io::Result<i32> {
    Ok(i32::from_le_bytes(get_exact(cursor, 4)?.try_into().unwrap()))
}
fn get_u64(cursor: &mut Cursor<&[u8]>) -> io::Result<u64> {
    Ok(u64::from_le_bytes(get_exact(cursor, 8)?.try_into().unwrap()))
}
fn get_i64(cursor: &mut Cursor<&[u8]>) -> io::Result<i64> {
    Ok(i64::from_le_bytes(get_exact(cursor, 8)?.try_into().unwrap()))
}
fn get_f32(cursor: &mut Cursor<&[u8]>) -> io::Result<f32> { Ok(f32::from_bits(get_u32(cursor)?)) }
fn get_f64(cursor: &mut Cursor<&[u8]>) -> io::Result<f64> { Ok(f64::from_bits(get_u64(cursor)?)) }

fn get_bool(cursor: &mut Cursor<&[u8]>) -> io::Result<bool> {
    match get_u8(cursor)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(invalid(format!("invalid raw spool boolean {}", value))),
    }
}

fn get_string(cursor: &mut Cursor<&[u8]>) -> io::Result<String> {
    let len = get_u32(cursor)? as usize;
    let bytes = get_exact(cursor, len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| invalid("raw spool string is not UTF-8"))
}

fn encode_result(out: &mut Vec<u8>, result: &AlnResult, recalc: &DpRecalcInfo) -> io::Result<()> {
    put_u64(out, result.ref_id as u64);
    put_bool(out, result.is_reverse);
    put_i32(out, result.chain_score);
    put_i32(out, result.initial_chain_score);
    put_u64(out, result.anchor_count as u64);
    put_bool(out, result.s2_score.is_some());
    if let Some(value) = result.s2_score { put_i32(out, value); }
    put_u32(out, result.hash);
    put_i32(out, result.align_score);
    put_u64(out, result.matches as u64);
    put_u64(out, result.block_len as u64);
    put_string(out, &result.cigar_str)?;
    put_string(out, &result.cs_str)?;
    put_string(out, &result.ds_str)?;
    put_string(out, &result.md_str)?;
    put_u64(out, result.query_start as u64);
    put_u64(out, result.query_end as u64);
    put_u64(out, result.ref_start as u64);
    put_u64(out, result.ref_end as u64);
    put_u32(out, result.edit_distance);
    put_u64(out, result.num_ambiguous as u64);
    put_f64(out, result.divergence);
    put_bool(out, result.is_secondary);
    put_u8(out, result.split);
    put_u8(out, result.split_depth);
    put_i32(out, result.dp_score);
    put_i32(out, result.dp_score_original);
    put_i32(out, result.effective_cnt);
    put_i32(out, result.pre_num_suboptimal);
    put_bool(out, result.is_spliced);
    put_u8(out, result.trans_strand);
    put_i32(out, result.dp_score_secondary);
    put_i32(out, result.secondary_chain_score);
    put_i32(out, result.num_suboptimal);
    put_bool(out, result.split_inv);
    put_bool(out, result.inv);
    put_bool(out, result.proper_frag);
    put_bool(out, result.seg_split);
    put_f32(out, result.div);
    put_bool(out, result.is_alt);
    put_bool(out, result.is_root_chain);

    put_i32(out, recalc.match_len);
    put_i32(out, recalc.block_len);
    put_i32(out, recalc.num_ambiguous);
    put_i32(out, recalc.gap_bases);
    put_i32(out, recalc.gap_opens);
    put_f64(out, recalc.sum_log_gap);
    Ok(())
}

fn as_usize(value: u64, field: &str) -> io::Result<usize> {
    usize::try_from(value).map_err(|_| invalid(format!("raw spool {} does not fit usize", field)))
}

fn decode_result(cursor: &mut Cursor<&[u8]>) -> io::Result<(AlnResult, DpRecalcInfo)> {
    let ref_id = as_usize(get_u64(cursor)?, "ref_id")?;
    let is_reverse = get_bool(cursor)?;
    let chain_score = get_i32(cursor)?;
    let initial_chain_score = get_i32(cursor)?;
    let anchor_count = as_usize(get_u64(cursor)?, "anchor_count")?;
    let s2_score = if get_bool(cursor)? { Some(get_i32(cursor)?) } else { None };
    let hash = get_u32(cursor)?;
    let align_score = get_i32(cursor)?;
    let matches = as_usize(get_u64(cursor)?, "matches")?;
    let block_len = as_usize(get_u64(cursor)?, "block_len")?;
    let cigar_str = get_string(cursor)?;
    let cs_str = get_string(cursor)?;
    let ds_str = get_string(cursor)?;
    let md_str = get_string(cursor)?;
    let query_start = as_usize(get_u64(cursor)?, "query_start")?;
    let query_end = as_usize(get_u64(cursor)?, "query_end")?;
    let ref_start = as_usize(get_u64(cursor)?, "ref_start")?;
    let ref_end = as_usize(get_u64(cursor)?, "ref_end")?;
    let edit_distance = get_u32(cursor)?;
    let num_ambiguous = as_usize(get_u64(cursor)?, "num_ambiguous")?;
    let divergence = get_f64(cursor)?;
    let is_secondary = get_bool(cursor)?;
    let split = get_u8(cursor)?;
    let split_depth = get_u8(cursor)?;
    let dp_score = get_i32(cursor)?;
    let dp_score_original = get_i32(cursor)?;
    let effective_cnt = get_i32(cursor)?;
    let pre_num_suboptimal = get_i32(cursor)?;
    let is_spliced = get_bool(cursor)?;
    let trans_strand = get_u8(cursor)?;
    let dp_score_secondary = get_i32(cursor)?;
    let secondary_chain_score = get_i32(cursor)?;
    let num_suboptimal = get_i32(cursor)?;
    let split_inv = get_bool(cursor)?;
    let inv = get_bool(cursor)?;
    let proper_frag = get_bool(cursor)?;
    let seg_split = get_bool(cursor)?;
    let div = get_f32(cursor)?;
    let is_alt = get_bool(cursor)?;
    let is_root_chain = get_bool(cursor)?;

    let recalc = DpRecalcInfo {
        match_len: get_i32(cursor)?,
        block_len: get_i32(cursor)?,
        num_ambiguous: get_i32(cursor)?,
        gap_bases: get_i32(cursor)?,
        gap_opens: get_i32(cursor)?,
        sum_log_gap: get_f64(cursor)?,
    };
    Ok((AlnResult {
        ref_id,
        is_reverse,
        chain_score,
        initial_chain_score,
        anchor_count,
        s2_score,
        hash,
        align_score,
        matches,
        block_len,
        cigar_str,
        cs_str,
        ds_str,
        md_str,
        query_start,
        query_end,
        ref_start,
        ref_end,
        edit_distance,
        num_ambiguous,
        divergence,
        is_secondary,
        split,
        split_depth,
        dp_score,
        dp_score_original,
        effective_cnt,
        pre_num_suboptimal,
        is_spliced,
        trans_strand,
        dp_score_secondary,
        secondary_chain_score,
        num_suboptimal,
        split_inv,
        inv,
        proper_frag,
        seg_split,
        div,
        is_alt,
        is_root_chain,
    }, recalc))
}

/// Writer for one shard's raw candidate spool.
pub struct RawSpoolWriter<W: Write> {
    writer: W,
    metadata: RawSpoolMetadata,
    checksum: u64,
    frame_count: u64,
    finished: bool,
}

impl<W: Write> RawSpoolWriter<W> {
    pub fn new(mut writer: W, metadata: RawSpoolMetadata) -> io::Result<Self> {
        let mut header = Vec::with_capacity(4 + 4 + 4 + 4 + 96);
        header.extend_from_slice(MAGIC);
        put_u32(&mut header, RAW_SPOOL_VERSION);
        put_u32(&mut header, metadata.shard_id);
        put_u32(&mut header, metadata.shard_count);
        header.extend_from_slice(&metadata.parameter_digest);
        header.extend_from_slice(&metadata.target_digest);
        header.extend_from_slice(&metadata.query_digest);
        writer.write_all(&header)?;
        Ok(Self {
            writer,
            metadata,
            checksum: checksum_update(FNV_OFFSET, &header),
            frame_count: 0,
            finished: false,
        })
    }

    pub fn metadata(&self) -> &RawSpoolMetadata { &self.metadata }

    pub fn write_query(&mut self, ordinal: u64, segment: u8, qlen: u64, raw: &RawQuery) -> io::Result<()> {
        if self.finished { return Err(io::Error::new(ErrorKind::Other, "raw spool is already finished")); }
        if segment > 1 { return Err(invalid("raw spool segment must be 0 or 1")); }
        if raw.results.len() != raw.recalc_infos.len() {
            return Err(invalid("raw spool result/recalculation lengths differ"));
        }
        let count = u32::try_from(raw.results.len()).map_err(|_| invalid("too many raw candidates"))?;
        let mut payload = Vec::new();
        put_u64(&mut payload, ordinal);
        put_u8(&mut payload, segment);
        put_u64(&mut payload, qlen);
        put_i64(&mut payload, raw.rep_len as i64);
        put_u32(&mut payload, count);
        for (result, recalc) in raw.results.iter().zip(&raw.recalc_infos) {
            encode_result(&mut payload, result, recalc)?;
        }
        let frame_len = u64::try_from(payload.len()).map_err(|_| invalid("raw spool frame is too long"))?;
        if frame_len > RAW_SPOOL_MAX_FRAME_BYTES { return Err(invalid("raw spool frame exceeds size limit")); }

        let mut prefix = Vec::with_capacity(4 + 8);
        prefix.extend_from_slice(FRAME_MAGIC);
        put_u64(&mut prefix, frame_len);
        write_all_checksum(&mut self.writer, &mut self.checksum, &prefix)?;
        write_all_checksum(&mut self.writer, &mut self.checksum, &payload)?;
        let frame_checksum = checksum_update(FNV_OFFSET, &payload);
        let checksum_bytes = frame_checksum.to_le_bytes();
        write_all_checksum(&mut self.writer, &mut self.checksum, &checksum_bytes)?;
        self.frame_count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        if self.finished { return Err(io::Error::new(ErrorKind::Other, "raw spool is already finished")); }
        self.finished = true;
        let mut trailer = Vec::with_capacity(20);
        trailer.extend_from_slice(TRAILER_MAGIC);
        put_u64(&mut trailer, self.frame_count);
        put_u64(&mut trailer, self.checksum);
        self.writer.write_all(&trailer)?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}

/// Reader for one shard's raw candidate spool.
pub struct RawSpoolReader<R: Read> {
    reader: R,
    metadata: RawSpoolMetadata,
    checksum: u64,
    expected_ordinal: Option<u64>,
    frame_count: u64,
    done: bool,
}

impl<R: Read> RawSpoolReader<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut header = [0u8; 112];
        reader.read_exact(&mut header)?;
        if &header[..4] != MAGIC { return Err(invalid("raw spool magic is invalid")); }
        let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if version != RAW_SPOOL_VERSION { return Err(invalid("raw spool version is unsupported")); }
        let metadata = RawSpoolMetadata {
            shard_id: u32::from_le_bytes(header[8..12].try_into().unwrap()),
            shard_count: u32::from_le_bytes(header[12..16].try_into().unwrap()),
            parameter_digest: header[16..48].try_into().unwrap(),
            target_digest: header[48..80].try_into().unwrap(),
            query_digest: header[80..112].try_into().unwrap(),
        };
        if metadata.shard_count == 0 || metadata.shard_id >= metadata.shard_count {
            return Err(invalid("raw spool shard identity is invalid"));
        }
        Ok(Self {
            reader,
            metadata,
            checksum: checksum_update(FNV_OFFSET, &header),
            expected_ordinal: None,
            frame_count: 0,
            done: false,
        })
    }

    pub fn metadata(&self) -> &RawSpoolMetadata { &self.metadata }

    pub fn validate_metadata(&self, expected: &RawSpoolMetadata) -> io::Result<()> {
        if self.metadata != *expected { return Err(invalid("raw spool metadata does not match run identity")); }
        Ok(())
    }

    pub fn next_query(&mut self) -> io::Result<Option<RawQueryFrame>> {
        if self.done { return Ok(None); }
        let mut marker = [0u8; 4];
        match self.reader.read_exact(&mut marker) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                return Err(invalid("raw spool is missing its committed trailer"));
            }
            Err(error) => return Err(error),
        }
        if &marker == TRAILER_MAGIC {
            let mut trailer = [0u8; 16];
            self.reader.read_exact(&mut trailer)?;
            let committed_frames = u64::from_le_bytes(trailer[..8].try_into().unwrap());
            let committed_checksum = u64::from_le_bytes(trailer[8..].try_into().unwrap());
            if committed_frames != self.frame_count { return Err(invalid("raw spool frame count is inconsistent")); }
            if committed_checksum != self.checksum { return Err(invalid("raw spool checksum is invalid")); }
            let mut trailing = [0u8; 1];
            if self.reader.read(&mut trailing)? != 0 {
                return Err(invalid("raw spool has trailing bytes after its trailer"));
            }
            self.done = true;
            return Ok(None);
        }
        if &marker != FRAME_MAGIC { return Err(invalid("raw spool frame marker is invalid")); }

        let mut len_bytes = [0u8; 8];
        self.reader.read_exact(&mut len_bytes)?;
        let frame_len = u64::from_le_bytes(len_bytes);
        if frame_len > RAW_SPOOL_MAX_FRAME_BYTES { return Err(invalid("raw spool frame exceeds size limit")); }
        let frame_len_usize = usize::try_from(frame_len).map_err(|_| invalid("raw spool frame does not fit memory"))?;
        let mut payload = vec![0u8; frame_len_usize];
        self.reader.read_exact(&mut payload)?;
        let mut checksum_bytes = [0u8; 8];
        self.reader.read_exact(&mut checksum_bytes)?;
        let expected_frame_checksum = u64::from_le_bytes(checksum_bytes);
        if checksum_update(FNV_OFFSET, &payload) != expected_frame_checksum {
            return Err(invalid("raw spool frame checksum is invalid"));
        }

        let mut frame_bytes = Vec::with_capacity(12 + frame_len_usize + 8);
        frame_bytes.extend_from_slice(FRAME_MAGIC);
        frame_bytes.extend_from_slice(&len_bytes);
        frame_bytes.extend_from_slice(&payload);
        frame_bytes.extend_from_slice(&checksum_bytes);
        self.checksum = checksum_update(self.checksum, &frame_bytes);

        let mut cursor = Cursor::new(payload.as_slice());
        let ordinal = get_u64(&mut cursor)?;
        if let Some(previous) = self.expected_ordinal {
            if ordinal <= previous { return Err(invalid("raw spool query ordinals are not strictly increasing")); }
        }
        self.expected_ordinal = Some(ordinal);
        let segment = get_u8(&mut cursor)?;
        if segment > 1 { return Err(invalid("raw spool segment is invalid")); }
        let qlen = get_u64(&mut cursor)?;
        let rep_len = get_i64(&mut cursor)?;
        let rep_len = i32::try_from(rep_len).map_err(|_| invalid("raw spool repetitive length is invalid"))?;
        let count = get_u32(&mut cursor)? as usize;
        let mut results = Vec::with_capacity(count);
        let mut recalc_infos = Vec::with_capacity(count);
        for _ in 0..count {
            let (result, recalc) = decode_result(&mut cursor)?;
            results.push(result);
            recalc_infos.push(recalc);
        }
        if cursor.position() != payload.len() as u64 { return Err(invalid("raw spool frame has trailing bytes")); }
        self.frame_count += 1;
        Ok(Some(RawQueryFrame {
            ordinal,
            segment,
            qlen,
            raw: RawQuery { results, recalc_infos, rep_len, stats: Default::default() },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn metadata() -> RawSpoolMetadata {
        RawSpoolMetadata {
            shard_id: 0,
            shard_count: 2,
            parameter_digest: [1; 32],
            target_digest: [2; 32],
            query_digest: [3; 32],
        }
    }

    fn raw() -> RawQuery {
        RawQuery {
            results: vec![AlnResult {
                ref_id: 4,
                is_reverse: true,
                chain_score: 12,
                initial_chain_score: 13,
                anchor_count: 5,
                s2_score: Some(3),
                hash: 7,
                align_score: 11,
                matches: 10,
                block_len: 12,
                cigar_str: "10M".to_string(),
                cs_str: ":10".to_string(),
                ds_str: String::new(),
                md_str: "10".to_string(),
                query_start: 1,
                query_end: 11,
                ref_start: 2,
                ref_end: 12,
                edit_distance: 2,
                num_ambiguous: 0,
                divergence: 0.1,
                is_secondary: false,
                split: 2,
                split_depth: 1,
                dp_score: 9,
                dp_score_original: 9,
                effective_cnt: 5,
                pre_num_suboptimal: 1,
                is_spliced: false,
                trans_strand: 0,
                dp_score_secondary: 4,
                secondary_chain_score: 5,
                num_suboptimal: 1,
                split_inv: true,
                inv: false,
                proper_frag: true,
                seg_split: false,
                div: 0.2,
                is_alt: true,
                is_root_chain: false,
            }],
            recalc_infos: vec![DpRecalcInfo {
                match_len: 10,
                block_len: 12,
                num_ambiguous: 0,
                gap_bases: 0,
                gap_opens: 0,
                sum_log_gap: 0.0,
            }],
            rep_len: 8,
            stats: Default::default(),
        }
    }

    #[test]
    fn round_trip_preserves_raw_candidate_fields() {
        let mut bytes = Vec::new();
        let mut writer = RawSpoolWriter::new(&mut bytes, metadata()).unwrap();
        writer.write_query(0, 1, 12, &raw()).unwrap();
        writer.finish().unwrap();

        let mut reader = RawSpoolReader::new(Cursor::new(bytes)).unwrap();
        reader.validate_metadata(&metadata()).unwrap();
        let frame = reader.next_query().unwrap().unwrap();
        assert_eq!(frame.ordinal, 0);
        assert_eq!(frame.segment, 1);
        assert_eq!(frame.qlen, 12);
        assert_eq!(frame.raw.rep_len, 8);
        assert_eq!(frame.raw.results[0].cigar_str, "10M");
        assert!(frame.raw.results[0].is_alt);
        assert!(reader.next_query().unwrap().is_none());
    }

    #[test]
    fn corruption_and_non_monotonic_ordinals_fail_closed() {
        let mut bytes = Vec::new();
        let mut writer = RawSpoolWriter::new(&mut bytes, metadata()).unwrap();
        writer.write_query(1, 0, 12, &raw()).unwrap();
        writer.write_query(2, 0, 12, &raw()).unwrap();
        writer.finish().unwrap();

        let mut corrupted = bytes.clone();
        let corrupt_at = corrupted.len() - 20;
        corrupted[corrupt_at] ^= 1;
        let mut reader = RawSpoolReader::new(Cursor::new(corrupted)).unwrap();
        assert!(reader.next_query().unwrap().is_some());
        assert!(reader.next_query().unwrap().is_some());
        assert!(reader.next_query().is_err());

        let mut reader = RawSpoolReader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_query().unwrap().is_some());
        assert!(reader.next_query().unwrap().is_some());
        assert!(reader.next_query().unwrap().is_none());

        let mut duplicate_bytes = Vec::new();
        let mut writer = RawSpoolWriter::new(&mut duplicate_bytes, metadata()).unwrap();
        writer.write_query(4, 0, 12, &raw()).unwrap();
        writer.write_query(4, 0, 12, &raw()).unwrap();
        writer.finish().unwrap();
        let mut reader = RawSpoolReader::new(Cursor::new(duplicate_bytes)).unwrap();
        assert!(reader.next_query().unwrap().is_some());
        assert!(reader.next_query().is_err());
    }
}
