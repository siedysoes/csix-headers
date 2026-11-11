# csix-headers

**Pemeriksa security headers website — grade A+ s/d F, murni Go, single binary.**

[![CI](https://github.com/siedysoes/csix-headers/actions/workflows/ci.yml/badge.svg)](https://github.com/siedysoes/csix-headers/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`csix-headers` mengambil sebuah URL lalu menilai 9 pemeriksaan header
keamanan — memberi **skor 0–100 + grade huruf (A+ … F)** beserta saran
perbaikan konkret untuk setiap kekurangan.

Mirip [securityheaders.com](https://securityheaders.com), tapi: CLI,
gratis tanpa batas, output JSON, dan bisa dipakai di CI.

## Fitur

- 🎓 **Grade A+ s/d F** + skor numerik transparan
- ✅ 9 pemeriksaan: HSTS, CSP, X-Content-Type-Options,
  X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy,
  COOP, COEP, CORP
- 💡 **Saran perbaikan konkret** untuk setiap header yang kurang
- 🔔 Catatan info: kebocoran versi server (`Server`, `X-Powered-By`),
  header deprecated (`X-XSS-Protection`)
- 📦 `--json` untuk integrasi tooling
- ⚡ Single binary, nol dependency

## Instalasi

```sh
go install github.com/siedysoes/csix-headers@latest
```

## Penggunaan

```sh
csix-headers https://example.com
csix-headers --json https://siedoyses.github.io
```

Contoh output:

```
csix-headers v0.1.0 — pemeriksa security headers

  Target   https://example.com
  Skor     9/100   Grade F
  ──────────────────────────────────────────────────────────────
  ✗ Strict-Transport-Security (HSTS)               0/20
      → Strict-Transport-Security: max-age=31536000; includeSubDomains
  ✗ Content-Security-Policy (CSP)                  0/20
      → Content-Security-Policy: default-src 'self'; object-src 'none'; ...
  ~ Referrer-Policy                                5/10  (mengikuti default browser)
  ...
```

## Opsi

| Flag | Fungsi |
|------|--------|
| `--json` | Output JSON |
| `--min-score <n>` | Skor minimal lolos (default 65 → di bawah ini exit 1) |
| `--timeout <dur>` | Timeout request (default `10s`) |
| `--insecure` | Abaikan verifikasi TLS |
| `--no-color` | Matikan warna (juga menghormati `NO_COLOR`) |
| `--version` | Tampilkan versi |

**Exit code:** `0` lolos · `1` skor di bawah ambang · `2` error

## Skoring

| Header | Bobot |
|--------|-------|
| Strict-Transport-Security | 20 |
| Content-Security-Policy | 20 |
| X-Content-Type-Options | 15 |
| X-Frame-Options / frame-ancestors | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| COOP · COEP · CORP | 5 + 5 + 5 |

**Grade** = persentase skor terhadap maksimum:
`A+` 100 · `A` 90 · `A-` 80 · `B` 65 · `C` 50 · `D` 35 · `F` <35

Target `http://` dinilai tanpa HSTS (maksimum 80) karena HSTS hanya berlaku
di atas HTTPS.

## Dukungan Bahasa

- English (this file)
- [Bahasa Indonesia](README.id.md)

## Lisensi

MIT — lihat [LICENSE](LICENSE). Untuk tujuan defensif.
