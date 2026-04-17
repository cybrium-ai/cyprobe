// FIDO2 device attestation — Phase 5.
// Gated behind the `fido2` feature flag. When enabled, `cyprobe enroll`
// triggers a CTAP2 MakeCredential flow on a connected hardware key
// (YubiKey, SoloKeys, etc.), sends the attestation to the platform,
// and receives a long-lived agent token bound to that key.
//
// Token refresh uses FIDO2 assertion (GetAssertion) — no password,
// no client secret, no key file on disk. The probe's identity is
// hardware-bound and non-exportable.
