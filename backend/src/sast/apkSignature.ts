/**
 * Reading an APK's signatures from the file itself.
 *
 * An APK can carry up to three independent signatures: the v1 (JAR) signature
 * in `META-INF`, and the v2, v3 and v3.1 signatures inside the "APK Signing
 * Block" that sits between the file data and the central directory. Which of
 * them is present decides what attacks are possible (v1 alone leaves the Janus
 * class of repackaging open), and the certificates inside them decide whether
 * the identity they assert is worth anything (a debug certificate, a 1024-bit
 * key, a SHA-1 signature).
 *
 * This parses those structures directly, so the signing findings rest on what
 * the file contains rather than on a summary of it, and they cover v2 and v3
 * signatures that a v1-only reader never sees. It does not verify the
 * signatures cryptographically; that is a different job and is left to a real
 * verifier.
 */
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';

export type CertificateFacts = {
  /** Where it was found: `v1 (META-INF/CERT.RSA)`, `v2`, `v3`, `v3.1`. */
  seenIn: string[];
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  sha256: string;
  sha1: string;
  signatureAlgorithm: string;
  keyAlgorithm: string;
  /** RSA/DSA modulus size, when the key has one. */
  keyBits?: number;
  curve?: string;
  selfSigned: boolean;
  debug: boolean;
};

export type SignatureScheme = 'v1' | 'v2' | 'v3' | 'v3.1';

export type SignatureReport = {
  /** The v1 signature block files in the APK (`META-INF/CERT.RSA`): real files the report can be shown as. */
  v1Files: string[];
  schemes: Record<SignatureScheme, boolean>;
  certificates: CertificateFacts[];
  /** The readable report, one fact per line, for the Explorer. */
  text: string;
  /** 1-based lines in `text` where the evidence for a finding sits. */
  lines: {
    scheme: Record<SignatureScheme, number>;
    certificates: { debug: number; algorithm: number; key: number }[];
  };
};

/* ------------------------------------------------------------------ DER */

type Tlv = { tag: number; start: number; header: number; end: number };

/** One ASN.1 DER element at `at`, or undefined if it does not fit in the buffer. */
function readTlv(buf: Buffer, at: number, limit = buf.length): Tlv | undefined {
  if (at + 2 > limit) return undefined;
  const tag = buf[at];
  let length = buf[at + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count < 1 || count > 4 || at + 2 + count > limit) return undefined;
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + buf[at + 2 + i];
    header = 2 + count;
  }
  const end = at + header + length;
  return end <= limit ? { tag, start: at, header, end } : undefined;
}

function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = parent.start + parent.header;
  while (at < parent.end) {
    const child = readTlv(buf, at, parent.end);
    if (!child) break;
    out.push(child);
    at = child.end;
  }
  return out;
}

/** The certificates inside a PKCS#7 SignedData, which is what `META-INF/*.RSA` is. */
export function certificatesFromPkcs7(der: Buffer): Buffer[] {
  const root = readTlv(der, 0);
  if (!root || root.tag !== 0x30) return [];
  // ContentInfo: OID, [0] EXPLICIT SignedData
  const explicit = children(der, root).find((c) => c.tag === 0xa0);
  const signedData = explicit && children(der, explicit)[0];
  if (!signedData) return [];
  // SignedData: version, digestAlgorithms, contentInfo, [0] IMPLICIT certificates, ...
  const certificates = children(der, signedData).find((c) => c.tag === 0xa0);
  if (!certificates) return [];
  return children(der, certificates)
    .filter((c) => c.tag === 0x30)
    .map((c) => der.subarray(c.start, c.end));
}

const OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.2': 'MD2withRSA',
  '1.2.840.113549.1.1.4': 'MD5withRSA',
  '1.2.840.113549.1.1.5': 'SHA1withRSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.11': 'SHA256withRSA',
  '1.2.840.113549.1.1.12': 'SHA384withRSA',
  '1.2.840.113549.1.1.13': 'SHA512withRSA',
  '1.2.840.10045.4.1': 'SHA1withECDSA',
  '1.2.840.10045.4.3.1': 'SHA224withECDSA',
  '1.2.840.10045.4.3.2': 'SHA256withECDSA',
  '1.2.840.10045.4.3.3': 'SHA384withECDSA',
  '1.2.840.10045.4.3.4': 'SHA512withECDSA',
  '1.2.840.10040.4.3': 'SHA1withDSA',
  '2.16.840.1.101.3.4.3.2': 'SHA256withDSA',
  '1.3.101.112': 'Ed25519',
};

function oidText(buf: Buffer, tlv: Tlv): string {
  const bytes = buf.subarray(tlv.start + tlv.header, tlv.end);
  if (bytes.length === 0) return '';
  const parts: number[] = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i += 1) {
    value = value * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** The algorithm the certificate itself was signed with: the second field of an X.509 Certificate. */
function signatureAlgorithmOf(der: Buffer): string {
  const cert = readTlv(der, 0);
  const algorithm = cert && children(der, cert)[1];
  const oid = algorithm && children(der, algorithm)[0];
  if (!oid || oid.tag !== 0x06) return 'unknown';
  const text = oidText(der, oid);
  return OIDS[text] ?? `OID ${text}`;
}

const hex = (s: string) => s.replace(/:/g, '').toLowerCase();
const oneLine = (dn: string) => dn.split('\n').join(', ');

function describeCertificate(der: Buffer, seenIn: string): CertificateFacts | undefined {
  try {
    const x = new X509Certificate(der);
    const key = x.publicKey;
    const details = key.asymmetricKeyDetails ?? {};
    const subject = oneLine(x.subject);
    const issuer = oneLine(x.issuer);
    return {
      seenIn: [seenIn],
      subject,
      issuer,
      serial: x.serialNumber.toLowerCase(),
      notBefore: x.validFrom,
      notAfter: x.validTo,
      sha256: hex(x.fingerprint256),
      sha1: hex(x.fingerprint),
      signatureAlgorithm: signatureAlgorithmOf(der),
      keyAlgorithm: (key.asymmetricKeyType ?? 'unknown').toUpperCase(),
      keyBits: details.modulusLength,
      curve: details.namedCurve,
      selfSigned: subject === issuer,
      debug: /CN=Android Debug\b|OU=Android\b/i.test(subject),
    };
  } catch {
    return undefined;
  }
}

/* ------------------------------------------------------------- the file */

const ID_V2 = 0x7109871a;
const ID_V3 = 0xf05368c0;
const ID_V31 = 0x1b93ad61;

function readAt(fd: number, position: number, length: number): Buffer {
  const out = Buffer.alloc(length);
  let done = 0;
  while (done < length) {
    const n = readSync(fd, out, done, length - done, position + done);
    if (n <= 0) break;
    done += n;
  }
  return out.subarray(0, done);
}

type Central = { cdOffset: number; names: string[] };

/** The central directory's offset and entry names, read from the end of the file. */
function readCentralDirectory(fd: number): Central | undefined {
  const size = fstatSync(fd).size;
  const tailLength = Math.min(size, 65_557);
  const tail = readAt(fd, size - tailLength, tailLength);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i -= 1) {
    if (tail.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return undefined;
  const cdSize = tail.readUInt32LE(eocd + 12);
  const cdOffset = tail.readUInt32LE(eocd + 16);
  if (cdOffset === 0xffffffff || cdSize > 64 * 1024 * 1024 || cdOffset + cdSize > size) return undefined;

  const cd = readAt(fd, cdOffset, cdSize);
  const names: string[] = [];
  for (let at = 0; at + 46 <= cd.length && cd.readUInt32LE(at) === 0x02014b50; ) {
    const nameLength = cd.readUInt16LE(at + 28);
    const extraLength = cd.readUInt16LE(at + 30);
    const commentLength = cd.readUInt16LE(at + 32);
    names.push(cd.toString('utf8', at + 46, at + 46 + nameLength));
    at += 46 + nameLength + extraLength + commentLength;
  }
  return { cdOffset, names };
}

/** The APK Signing Block's id/value pairs, if the file has one. */
function readSigningBlock(fd: number, cdOffset: number): Map<number, Buffer> {
  const pairs = new Map<number, Buffer>();
  if (cdOffset < 32) return pairs;
  const footer = readAt(fd, cdOffset - 24, 24);
  if (footer.toString('latin1', 8, 24) !== 'APK Sig Block 42') return pairs;
  const blockSize = Number(footer.readBigUInt64LE(0));
  // blockSize counts everything after the leading size field, so the block spans [cdOffset - blockSize - 8, cdOffset).
  if (blockSize < 24 || blockSize > 64 * 1024 * 1024 || blockSize + 8 > cdOffset) return pairs;
  const body = readAt(fd, cdOffset - blockSize, blockSize - 24);
  for (let at = 0; at + 12 <= body.length; ) {
    const length = Number(body.readBigUInt64LE(at));
    if (length < 4 || at + 8 + length > body.length) break;
    pairs.set(body.readUInt32LE(at + 8), body.subarray(at + 12, at + 8 + length));
    at += 8 + length;
  }
  return pairs;
}

/** A 4-byte little-endian length, then that many bytes. */
function lengthPrefixed(buf: Buffer, at: number): { value: Buffer; next: number } | undefined {
  if (at + 4 > buf.length) return undefined;
  const length = buf.readUInt32LE(at);
  if (at + 4 + length > buf.length) return undefined;
  return { value: buf.subarray(at + 4, at + 4 + length), next: at + 4 + length };
}

/** Each signer's certificates from a v2/v3 block value: signers[ signer{ signedData{ digests, certificates, ... } } ]. */
function certificatesFromSchemeBlock(value: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const signers = lengthPrefixed(value, 0);
  if (!signers) return out;
  for (let at = 0; at < signers.value.length; ) {
    const signer = lengthPrefixed(signers.value, at);
    if (!signer) break;
    at = signer.next;
    const signedData = lengthPrefixed(signer.value, 0);
    if (!signedData) continue;
    const digests = lengthPrefixed(signedData.value, 0);
    const certificates = digests && lengthPrefixed(signedData.value, digests.next);
    if (!certificates) continue;
    for (let c = 0; c < certificates.value.length; ) {
      const cert = lengthPrefixed(certificates.value, c);
      if (!cert) break;
      out.push(cert.value);
      c = cert.next;
    }
  }
  return out;
}

function extract(apkPath: string, entry: string): Buffer | undefined {
  try {
    return execFileSync('/usr/bin/unzip', ['-p', apkPath, entry], {
      maxBuffer: 16 * 1024 * 1024,
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return undefined;
  }
}

/* ---------------------------------------------------------------- report */

const SCHEME_LABEL: Record<SignatureScheme, string> = {
  v1: 'v1  (JAR signing, META-INF)',
  v2: 'v2  (APK Signature Scheme v2)',
  v3: 'v3  (APK Signature Scheme v3)',
  'v3.1': 'v3.1 (APK Signature Scheme v3.1)',
};

export function readApkSignatures(apkPath: string): SignatureReport {
  const schemes: Record<SignatureScheme, boolean> = { v1: false, v2: false, v3: false, 'v3.1': false };
  const found = new Map<string, CertificateFacts>();
  const notes: string[] = [];

  const add = (der: Buffer, seenIn: string) => {
    const facts = describeCertificate(der, seenIn);
    if (!facts) return void notes.push(`A certificate found in ${seenIn} could not be parsed.`);
    const existing = found.get(facts.sha256);
    if (existing) existing.seenIn.push(seenIn);
    else found.set(facts.sha256, facts);
  };

  let fd: number | undefined;
  try {
    fd = openSync(apkPath, 'r');
    const central = readCentralDirectory(fd);
    if (!central) {
      notes.push('The file has no readable central directory, so its signatures could not be read.');
    } else {
      const v1Files = central.names.filter((n) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(n));
      const sigFiles = central.names.filter((n) => /^META-INF\/[^/]+\.SF$/i.test(n));
      schemes.v1 = v1Files.length > 0 && sigFiles.length > 0;
      for (const name of v1Files) {
        const der = extract(apkPath, name);
        if (!der) continue;
        for (const cert of certificatesFromPkcs7(der)) add(cert, `v1 (${name})`);
      }

      const block = readSigningBlock(fd, central.cdOffset);
      for (const [id, scheme] of [[ID_V2, 'v2'], [ID_V3, 'v3'], [ID_V31, 'v3.1']] as const) {
        const value = block.get(id);
        if (!value) continue;
        schemes[scheme] = true;
        for (const cert of certificatesFromSchemeBlock(value)) add(cert, scheme);
      }
    }
  } catch (error) {
    notes.push(`The signatures could not be read: ${(error as Error).message}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }

  const certificates = [...found.values()];
  const v1Files = [...found.values()].flatMap((c) => c.seenIn).map((x) => /^v1 \((.+)\)$/.exec(x)?.[1]).filter((x): x is string => Boolean(x));
  const lines = [
    '// Signature analysis of this APK, read from the signature data inside the file.',
    '// "present" means the data is in the file. Whether a given Android version then accepts it also depends on',
    '// the app\u2019s minimum SDK version. This reports what the certificates say; it does not re-verify signatures.',
    '',
    '== Signature schemes ==',
  ];
  const schemeLine = {} as Record<SignatureScheme, number>;
  for (const scheme of ['v1', 'v2', 'v3', 'v3.1'] as const) {
    lines.push(`${SCHEME_LABEL[scheme].padEnd(36)}: ${schemes[scheme] ? 'present' : 'absent'}`);
    schemeLine[scheme] = lines.length;
  }
  if (!schemes.v2 && !schemes.v3 && !schemes['v3.1']) {
    lines.push('', 'No v2, v3 or v3.1 signing block is present.');
  }

  const certLines: SignatureReport['lines']['certificates'] = [];
  certificates.forEach((c, i) => {
    lines.push('', `== Signing certificate ${i + 1} ==`);
    const at = { debug: 0, algorithm: 0, key: 0 };
    const row = (text: string): number => lines.push(text);
    row(`seen in             : ${c.seenIn.join(', ')}`);
    row(`subject             : ${c.subject}`);
    row(`issuer              : ${c.issuer}`);
    row(`self-signed         : ${c.selfSigned ? 'yes' : 'no'}`);
    at.debug = row(`debug certificate   : ${c.debug ? 'YES (the publicly known Android debug identity)' : 'no'}`);
    row(`serial              : ${c.serial}`);
    row(`valid               : ${c.notBefore}  to  ${c.notAfter}`);
    at.algorithm = row(`signature algorithm : ${c.signatureAlgorithm}`);
    at.key = row(`public key          : ${c.keyAlgorithm}${c.keyBits ? ` ${c.keyBits}-bit` : ''}${c.curve ? ` (${c.curve})` : ''}`);
    row(`sha-256             : ${c.sha256}`);
    row(`sha-1               : ${c.sha1}`);
    certLines.push(at);
  });
  if (certificates.length === 0) lines.push('', 'No signing certificate could be read.');
  if (notes.length > 0) lines.push('', '== Notes ==', ...notes);

  return { v1Files: [...new Set(v1Files)], schemes, certificates, text: lines.join('\n'), lines: { scheme: schemeLine, certificates: certLines } };
}
