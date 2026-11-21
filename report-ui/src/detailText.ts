// Readable layout for check details. Many checks write sentences of the form
// "N thing(s) ...: item one; item two; item three." The details panel shows
// each such sentence as its lead-in followed by a bulleted list, and other
// sentences as written. Text is never changed, only split at separators that
// sit outside quotes and brackets.

export type DetailBlock = { text: string } | { lead: string; items: string[] };

/** Indexes of `separator` that sit outside quotes and (), [], {}. */
function topLevelIndexes(text: string, separator: string): number[] {
  const found: number[] = [];
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      // A quote closes before a non-word character; an apostrophe inside a
      // word (it's, workload's) is not a closing quote.
      if (ch === quote && !/\w/.test(text[i + 1] ?? '')) quote = null;
      continue;
    }
    if ((ch === "'" || ch === '"') && !/\w/.test(text[i - 1] ?? '')) {
      quote = ch;
    } else if ('([{'.includes(ch)) {
      depth++;
    } else if (')]}'.includes(ch)) {
      depth = Math.max(0, depth - 1);
    } else if (depth === 0 && text.startsWith(separator, i)) {
      found.push(i);
    }
  }
  return quote ? [] : found;
}

/** Top-level sentences: split after ". " when the next sentence starts with a capital or a digit. */
function sentences(paragraph: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (const i of topLevelIndexes(paragraph, '. ')) {
    if (/[A-Z0-9]/.test(paragraph[i + 2] ?? '')) {
      out.push(paragraph.slice(start, i + 1));
      start = i + 2;
    }
  }
  out.push(paragraph.slice(start));
  return out.filter(sentence => sentence.length > 0);
}

/** A sentence as a lead-in and two or more items, or null when it isn't a list. */
function asList(sentence: string): { lead: string; items: string[] } | null {
  const colon = topLevelIndexes(sentence, ': ')[0];
  if (colon === undefined || colon > 300) return null;
  const rest = sentence.slice(colon + 2);
  const cuts = topLevelIndexes(rest, '; ');
  if (cuts.length < 1) return null;
  const items: string[] = [];
  let start = 0;
  for (const cut of cuts) {
    items.push(rest.slice(start, cut).trim());
    start = cut + 2;
  }
  items.push(rest.slice(start).trim());
  if (items.some(item => item.length === 0)) return null;
  return { lead: sentence.slice(0, colon + 1).trim(), items };
}

/** A paragraph as text and list blocks; null when it holds no list. */
export function splitDetailList(paragraph: string): DetailBlock[] | null {
  const blocks: DetailBlock[] = [];
  let listed = false;
  for (const sentence of sentences(paragraph)) {
    const list = asList(sentence);
    if (list) {
      blocks.push(list);
      listed = true;
      continue;
    }
    const last = blocks[blocks.length - 1];
    if (last && 'text' in last) {
      last.text += ' ' + sentence;
    } else {
      blocks.push({ text: sentence });
    }
  }
  return listed ? blocks : null;
}

/**
 * A run of text, or an AWS identifier to show as inline code: a quoted name
 * ('my-role'), an ARN, an EC2/VPC resource ID, an IAM action or condition key
 * (bedrock:InvokeModel), a VPC endpoint service name, or an account ID.
 * `quote` holds the quote character the source text used around a name; it is
 * kept so the pieces join back to the original text.
 */
export type TextPiece = { text: string } | { code: string; quote: string };

const IDENTIFIER = new RegExp(
  [
    // ARNs, before IAM actions so their "service:region" part isn't matched alone.
    // An ARN never ends in sentence punctuation, so a full stop stays text.
    String.raw`(?<arn>\barn:aws[\w-]*:[^\s,;)'"]*[^\s,;)'".:])`,
    // Quoted names. A quote opens and closes next to a non-word character, so
    // apostrophes inside words (workload's) are not quotes.
    String.raw`(?<!\w)'(?<single>[^'\n]{1,256}?)'(?!\w)`,
    String.raw`(?<!\w)"(?<double>[^"\n]{1,256}?)"(?!\w)`,
    String.raw`(?<endpoint>\bcom\.amazonaws\.[a-z0-9.-]*[a-z0-9])`,
    String.raw`(?<resource>\b(?:vpc|subnet|sgr?|eni|e?igw|rtb|vpce|nat|i|ami|vol|snap|acl|tgw|pcx|lt|fsap|fs)-[0-9a-f]{8,17}\b)`,
    String.raw`(?<action>\b[a-z][a-z0-9-]*:[A-Za-z*][A-Za-z0-9*]*\b)`,
    String.raw`(?<account>(?<![\w-])\d{12}(?![\w-]))`,
  ].join('|'),
  'g'
);

export function identifierPieces(text: string): TextPiece[] {
  const pieces: TextPiece[] = [];
  let last = 0;
  for (const match of text.matchAll(IDENTIFIER)) {
    const start = match.index ?? 0;
    const groups = match.groups ?? {};
    const quoted = groups.single ?? groups.double;
    // A bare "*" or a short quoted word reads fine as text; keep it quoted.
    if (quoted !== undefined && quoted.trim().length === 0) continue;
    if (start > last) pieces.push({ text: text.slice(last, start) });
    if (quoted !== undefined) {
      pieces.push({ code: quoted, quote: match[0][0] });
    } else {
      pieces.push({ code: match[0], quote: '' });
    }
    last = start + match[0].length;
  }
  if (last < text.length) pieces.push({ text: text.slice(last) });
  return pieces;
}
