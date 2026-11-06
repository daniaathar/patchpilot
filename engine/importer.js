/**
 * engine/importer.js
 * FR-1 Import: Parses and validates CSV or JSON finding files.
 * Owner: Hareem
 *
 * parseImport(text, type) -> { valid: [findings], errors: [{row, code, message}] }
 */

'use strict';

// Fields that must be present and non-empty in every finding row
// Using lowercase because the CSV parser normalises all header keys to lowercase.
const REQUIRED_FIELDS = ['title', 'cve', 'cvss', 'asset', 'assetcriticality', 'scanner'];

// Allowed values for assetCriticality
const VALID_CRITICALITIES = ['low', 'medium', 'high', 'critical'];

// Maximum number of rows allowed in a single import (size limit)
const MAX_ROWS = 5000;

// Characters that trigger formula injection in spreadsheet tools
const FORMULA_DANGEROUS_CHARS = /^[=+\-@]/;

/**
 * Sanitizes a string value by stripping leading formula-injection characters.
 * Returns the cleaned string or the original if it is not a string.
 */
function sanitizeText(value) {
  if (typeof value !== 'string') return value;
  // Remove dangerous leading characters to prevent CSV formula injection
  return value.replace(/^[=+\-@]+/, '');
}

/**
 * Parses a CSV text string into an array of plain objects.
 * The first row is treated as the header row.
 *
 * Robustly handles:
 *   - Quoted fields containing commas
 *   - Quoted fields containing embedded newlines (multiline fields)
 *   - Escaped double-quotes ("") inside quoted fields
 *   - Windows (CRLF) and Unix (LF) line endings
 */
function parseCsvText(text) {
  // ── Step 1: tokenise the entire CSV character-by-character ────────────────
  // This avoids the line-split-then-parse approach that breaks on multiline
  // quoted fields.
  const fields = [];   // flat list of all parsed field values
  const rowBreaks = []; // indices into `fields` where a new row starts

  let current  = '';
  let inQuotes = false;
  let i = 0;
  rowBreaks.push(0); // row 0 starts at field index 0

  while (i < text.length) {
    const ch   = text[i];
    const next = text[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        // Escaped double-quote inside a quoted field
        current += '"';
        i += 2;
      } else if (ch === '"') {
        // Closing quote
        inQuotes = false;
        i++;
      } else {
        // Regular character inside quotes (including newlines)
        current += ch;
        i++;
      }
    } else {
      if (ch === '"') {
        // Opening quote
        inQuotes = true;
        i++;
      } else if (ch === ',') {
        // Field separator
        fields.push(current.trim());
        current = '';
        i++;
      } else if (ch === '\r' && next === '\n') {
        // Windows CRLF line ending → row break
        fields.push(current.trim());
        current = '';
        rowBreaks.push(fields.length);
        i += 2;
      } else if (ch === '\n') {
        // Unix LF line ending → row break
        fields.push(current.trim());
        current = '';
        rowBreaks.push(fields.length);
        i++;
      } else {
        current += ch;
        i++;
      }
    }
  }
  // Push the last field (no trailing newline)
  if (current.trim() !== '' || fields.length > 0) {
    fields.push(current.trim());
  }

  // ── Step 2: split flat field list into rows using rowBreaks ──────────────
  // Each entry in rowBreaks is the index in `fields` where that row begins.
  rowBreaks.push(fields.length); // sentinel end

  const allRows = [];
  for (let r = 0; r + 1 < rowBreaks.length; r++) {
    const rowFields = fields.slice(rowBreaks[r], rowBreaks[r + 1]);
    // Skip rows that are entirely empty (blank lines)
    if (rowFields.every(f => f === '')) continue;
    allRows.push(rowFields);
  }

  if (allRows.length < 2) return []; // need at least header + 1 data row

  // ── Step 3: map rows to objects using header row ──────────────────────────
  const headers = allRows[0].map(h => h.toLowerCase().trim());
  const rows = [];
  for (let r = 1; r < allRows.length; r++) {
    const values = allRows[r];
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h] = values[idx] !== undefined ? values[idx] : '';
    });
    obj.__rowNumber = r; // 1-based (header row is row 0)
    rows.push(obj);
  }
  return rows;
}

/**
 * Validates a single raw row object against the Finding rules.
 * Returns an array of error objects (empty array = valid).
 * Each error: { row, code, message }
 */
function validateRow(row, rowNumber) {
  const errors = [];

  // Check required fields
  // Field names are lowercase because parseCsvText lowercases all headers.
  // For error messages we display a user-friendly camelCase alias.
  const fieldDisplayName = {
    title: 'title', cve: 'cve', cvss: 'cvss',
    asset: 'asset', assetcriticality: 'assetCriticality', scanner: 'scanner'
  };
  for (const field of REQUIRED_FIELDS) {
    const val = row[field];
    if (val === undefined || val === null || String(val).trim() === '') {
      const display = fieldDisplayName[field] || field;
      errors.push({
        row: rowNumber,
        code: 'E_VALIDATION',
        message: `Row ${rowNumber}: missing required field '${display}'.`
      });
    }
  }

  // Validate cvss is a number between 0 and 10 (inclusive)
  // Note: CSV headers are lowercased by parseCsvText, so key is 'cvss' either way.
  const cvssRaw = row['cvss'];
  if (cvssRaw !== undefined && String(cvssRaw).trim() !== '') {
    const cvss = parseFloat(cvssRaw);
    if (isNaN(cvss) || cvss < 0 || cvss > 10) {
      errors.push({
        row: rowNumber,
        code: 'E_VALIDATION',
        message: `Row ${rowNumber}: 'cvss' must be a number between 0 and 10 (got '${cvssRaw}').`
      });
    }
  }

  // Validate assetCriticality is one of the allowed values (key is lowercase after CSV parse)
  const critRaw = row['assetcriticality'] !== undefined ? row['assetcriticality'] : row['assetCriticality'];
  if (critRaw !== undefined) {
    const crit = String(critRaw).trim().toLowerCase();
    if (crit !== '' && !VALID_CRITICALITIES.includes(crit)) {
      errors.push({
        row: rowNumber,
        code: 'E_VALIDATION',
        message: `Row ${rowNumber}: 'assetCriticality' must be one of ${VALID_CRITICALITIES.join(', ')} (got '${critRaw}').`
      });
    }
  }

  // Validate firstSeen is a real date (optional field; blank = today)
  const fsRaw = row['firstseen'] !== undefined ? row['firstseen'] : row['firstSeen'];
  if (fsRaw !== undefined && fsRaw !== null && String(fsRaw).trim() !== '') {
    const fs = String(fsRaw).trim();
    if (!/^\d{4}-\d{2}-\d{2}/.test(fs) || isNaN(Date.parse(fs))) {
      errors.push({
        row: rowNumber,
        code: 'E_VALIDATION',
        message: `Row ${rowNumber}: 'firstSeen' must be a valid date like 2026-11-01 (got '${fsRaw}').`
      });
    }
  }

  // Check for formula injection in text fields
  // Use lowercase keys because parseCsvText normalises headers to lowercase.
  const textFields = [['title', 'title'], ['cve', 'cve'], ['asset', 'asset'], ['scanner', 'scanner']];
  for (const [display, key] of textFields) {
    const val = row[key];
    if (val && FORMULA_DANGEROUS_CHARS.test(String(val))) {
      errors.push({
        row: rowNumber,
        code: 'E_VALIDATION',
        message: `Row ${rowNumber}: field '${display}' starts with a forbidden character (= + - @) which could cause formula injection.`
      });
    }
  }

  return errors;
}

/**
 * Converts a raw validated row object into a proper Finding object.
 * Normalises field names and casts types.
 * CSV headers are lowercased by parseCsvText; JSON rows keep original casing
 * but also have a lowercased copy.
 */
function rowToFinding(row) {
  // Helper: tries camelCase key first (JSON), then lowercase (CSV)
  const get = (camel, lower) => {
    if (row[camel] !== undefined) return row[camel];
    if (row[lower]  !== undefined) return row[lower];
    return '';
  };

  return {
    id: null,
    title:            sanitizeText(String(get('title', 'title')).trim()),
    cve:              sanitizeText(String(get('cve', 'cve')).trim().toUpperCase()),
    cvss:             parseFloat(get('cvss', 'cvss')),
    asset:            sanitizeText(String(get('asset', 'asset')).trim()),
    assetCriticality: String(get('assetCriticality', 'assetcriticality')).trim().toLowerCase(),
    internetFacing: (() => {
      const raw = get('internetFacing', 'internetfacing');
      if (typeof raw === 'boolean') return raw;
      return String(raw).trim().toLowerCase() === 'true';
    })(),
    scanner:   sanitizeText(String(get('scanner', 'scanner')).trim()),
    firstSeen: (() => {
      const raw = get('firstSeen', 'firstseen');
      if (!raw) return new Date().toISOString().slice(0, 10);
      return String(raw).trim();
    })(),
    status:        'open',
    priorityScore: null,
    priority:      null,
    dueDate:       null,
    owner:         null,
    reasons:       [],
    history:       []
  };
}

/**
 * parseImport(text, type)
 *
 * Parses a file's text content (CSV or JSON) and returns validated findings.
 *
 * @param {string} text  - Raw file content as a string
 * @param {string} type  - 'csv' or 'json'
 * @returns {{ valid: Finding[], errors: {row: number, code: string, message: string}[] }}
 */
function parseImport(text, type) {
  const valid = [];
  const errors = [];

  // Reject empty input
  if (!text || typeof text !== 'string' || text.trim() === '') {
    errors.push({ row: 0, code: 'E_VALIDATION', message: 'File is empty.' });
    return { valid, errors };
  }

  let rawRows = [];

  if (type === 'csv') {
    rawRows = parseCsvText(text);
    // If parseCsvText returned nothing, the file had no valid header+data structure
    if (rawRows.length === 0) {
      errors.push({
        row: 0,
        code: 'E_VALIDATION',
        message: 'CSV file could not be parsed: no valid header row and data rows found.'
      });
      return { valid, errors };
    }
  } else if (type === 'json') {
    try {
      const parsed = JSON.parse(text);
      if (!Array.isArray(parsed)) {
        errors.push({ row: 0, code: 'E_VALIDATION', message: 'JSON file must contain an array of findings.' });
        return { valid, errors };
      }
      // Normalise keys to lowercase for uniform validation
      rawRows = parsed.map((item, idx) => {
        const lower = {};
        for (const key of Object.keys(item)) {
          lower[key.toLowerCase()] = item[key];
          lower[key] = item[key]; // keep original casing too
        }
        lower.__rowNumber = idx + 1;
        return lower;
      });
    } catch (e) {
      errors.push({ row: 0, code: 'E_VALIDATION', message: `JSON parse error: ${e.message}` });
      return { valid, errors };
    }
  } else {
    errors.push({ row: 0, code: 'E_VALIDATION', message: `Unknown file type '${type}'. Use 'csv' or 'json'.` });
    return { valid, errors };
  }

  // Enforce row limit
  if (rawRows.length > MAX_ROWS) {
    errors.push({
      row: 0,
      code: 'E_TOO_BIG',
      message: `File contains ${rawRows.length} rows which exceeds the maximum of ${MAX_ROWS}.`
    });
    return { valid, errors };
  }

  // Validate and convert each row
  for (const row of rawRows) {
    const rowNum = row.__rowNumber || 0;
    const rowErrors = validateRow(row, rowNum);
    if (rowErrors.length > 0) {
      errors.push(...rowErrors);
    } else {
      valid.push(rowToFinding(row));
    }
  }

  return { valid, errors };
}

module.exports = { parseImport };
