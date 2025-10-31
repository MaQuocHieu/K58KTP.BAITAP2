#!/usr/bin/env python3
import os, sys, binascii, hashlib, datetime, traceback
from typing import List, Optional
from PyPDF2 import PdfReader
from asn1crypto import cms, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

try:
    import requests
except Exception:
    requests = None

LOG = "verify_log.txt"

def log(msg):
    s = f"[{datetime.datetime.utcnow().isoformat()}Z] {msg}"
    print(s)
    with open(LOG, "a", encoding="utf-8") as f: f.write(s + "\n")

def clr():
    if os.path.exists(LOG): os.remove(LOG)

def find_sig(pdf):
    r = PdfReader(pdf)
    for p in r.pages:
        annots = p.get("/Annots") or []
        for ref in annots:
            a = ref.get_object()
            if a.get("/Subtype") == "/Widget" and a.get("/FT") == "/Sig":
                v = a.get("/V")
                if v:
                    return {"sig": v.get_object(), "reader": r}
    return None

def extract(sig):
    c = sig.get("/Contents")
    b = sig.get("/ByteRange")
    pkcs7 = c.get_data() if hasattr(c, "get_data") else bytes(c)
    return pkcs7, [int(x) for x in b]

def hash_br(pdf, br, algo="sha256"):
    with open(pdf, "rb") as f: d = f.read()
    m = hashlib.new(algo)
    m.update(d[br[0]:br[0]+br[1]]); m.update(d[br[2]:br[2]+br[3]])
    return m.digest(), m.hexdigest()

def parse_p7(pkcs7):
    ci = cms.ContentInfo.load(pkcs7)
    sd = ci['content']
    return sd, sd['signer_infos'][0], sd['certificates']

def signer_md(sd, si):
    sa = si['signed_attrs'] if 'signed_attrs' in si else None
    msg_d = None
    if sa:
        for a in sa:
            t = a['type']
            if t.native == 'message_digest' or t.dotted == '1.2.840.113549.1.9.4':
                msg_d = a['values'][0].native
    cert = None
    for c in sd['certificates']:
        if c.name == 'certificate':
            cert = c.chosen
            break
    return cert, msg_d, sa

def asn1_to_cert(a): return x509.load_der_x509_certificate(a.dump(), default_backend())

def verify_sig(cert, si):
    sig = si['signature'].native
    sa = si['signed_attrs'] if 'signed_attrs' in si else None
    if not sa: return False, "No signed_attrs"
    der = sa.dump()
    algo = si['digest_algorithm']['algorithm'].native
    algs = {'sha1': hashes.SHA1(), 'sha256': hashes.SHA256(), 'sha384': hashes.SHA384(), 'sha512': hashes.SHA512()}
    try:
        cert.public_key().verify(sig, der, padding.PKCS1v15(), algs[algo])
        return True, f"OK ({algo})"
    except Exception as e:
        return False, str(e)

def chain_check(certs, trusts: Optional[List[str]]):
    lst = [asn1_to_cert(c.chosen) for c in certs if c.name == 'certificate']
    if not lst:
        return [], False
    names = {c.issuer.rfc4514_string() for c in lst}
    leaf_candidates = [c for c in lst if c.subject.rfc4514_string() not in names]
    leaf = leaf_candidates[0] if leaf_candidates else lst[0]  # fallback cho self-signed
    chain = [leaf]
    m = {c.subject.rfc4514_string(): c for c in lst}
    while True:
        i = chain[-1].issuer.rfc4514_string()
        if i == chain[-1].subject.rfc4514_string() or i not in m:
            break
        chain.append(m[i])
    trust_names = set()
    if trusts:
        for t in trusts:
            try:
                b = open(t, "rb").read()
                try:
                    x = x509.load_pem_x509_certificate(b, default_backend())
                except:
                    x = x509.load_der_x509_certificate(b, default_backend())
                trust_names.add(x.subject.rfc4514_string())
            except Exception as e:
                log(f"Could not load trust anchor {t}: {e}")
    ok = chain[-1].subject.rfc4514_string() in trust_names if trust_names else False
    return chain, ok


def has_ts(si):
    if 'unsigned_attrs' not in si: return False
    ua = si['unsigned_attrs']
    for a in ua:
        if a['type'].native == 'signature_time_stamp_token' or a['type'].dotted == '1.2.840.113549.1.9.16.2.14':
            return True
    return False

def inc_chk(pdf, br):
    s = os.path.getsize(pdf); e = br[2]+br[3]
    return (True, "No extra data") if s <= e else (False, f"{s-e} extra bytes")

def main(pdf, trusts=None):
    clr(); log(f"=== VERIFY {pdf} ===")
    try:
        info = find_sig(pdf)
        if not info: return log("No signature found.")
        pkcs7, br = extract(info['sig'])
        sd, si, certs = parse_p7(pkcs7)
        cert_asn1, msg_d, sa = signer_md(sd, si)
        cert = asn1_to_cert(cert_asn1)
        log(f"Cert: {cert.subject.rfc4514_string()}")
        h, hh = hash_br(pdf, br)
        log(f"Hash={hh}")
        if msg_d:
            log(f"MsgDigest={binascii.hexlify(msg_d).decode()}")
            log("Digest OK" if h == msg_d else "Digest mismatch")
        ok, msg = verify_sig(cert, si); log(f"Sig verify: {msg}")
        ch, trust = chain_check(certs, trusts)
        for i,x in enumerate(ch): log(f"Chain[{i}] {x.subject.rfc4514_string()} -> {x.issuer.rfc4514_string()}")
        log("Trust OK" if trust else "No trust anchor")
        log("Timestamp found" if has_ts(si) else "No timestamp")
        ok2, msg2 = inc_chk(pdf, br); log(msg2)
        log("=== DONE ===")
    except Exception as e:
        log(f"Error: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test.py signed.pdf [trust_anchor.pem ...]")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2:] if len(sys.argv) > 2 else None)
