use criterion::{black_box, criterion_group, criterion_main, Criterion};
use HuangProject2::{audit, cred_issue, cred_verify, fee_deduct, pre_payment, revoke, schnorr_sign, schnorr_verify, trace, IssuerKeyPair, PaymentLog, SystemParams, VerifierKeyPair};

// 测试 SystemParams::setup 函数的性能
fn bench_system_params_setup(c: &mut Criterion) {
    c.bench_function("SystemParams::setup", |b| {
        b.iter(|| {
            // 测试 SystemParams::setup 性能
            black_box(SystemParams::setup());
        });
    });
}

// 测试 IssuerKeyPair::generate 函数的性能
fn bench_issuer_keypair_generate(c: &mut Criterion) {
    let params = SystemParams::setup();
    c.bench_function("IssuerKeyPair::generate", |b| {
        b.iter(|| {
            // 测试 IssuerKeyPair::generate 性能
            black_box(IssuerKeyPair::generate(&params));
        });
    });
}

// 测试 VerifierKeyPair::generate 函数的性能
fn bench_verifier_keypair_generate(c: &mut Criterion) {
    let params = SystemParams::setup();
    c.bench_function("VerifierKeyPair::generate", |b| {
        b.iter(|| {
            // 测试 VerifierKeyPair::generate 性能
            black_box(VerifierKeyPair::generate(&params));
        });
    });
}

// 测试 schnorr_sign 函数的性能
fn bench_schnorr_sign(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for schnorr_sign";

    // 使用 params.g1 替代 G1::generator()
    let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

    c.bench_function("schnorr_sign", |b| {
        b.iter(|| {
            // 测试 schnorr_sign 性能
            black_box(schnorr_sign(&params, &issuer_kp.sk.expose_secret(), msg));
        });
    });
}

// 测试 schnorr_verify 函数的性能
fn bench_schnorr_verify(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for schnorr_sign";
    let sig = schnorr_sign(&params, &issuer_kp.sk.expose_secret(), msg);

    c.bench_function("schnorr_verify", |b| {
        b.iter(|| {
            // 测试 schnorr_verify 性能
            black_box(schnorr_verify(&params, msg, &sig, &issuer_kp.pk));
        });
    });
}

// 测试 cred_issue 函数的性能
fn bench_cred_issue(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";

    // 使用 params.g1 替代 G1::generator()
    let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

    c.bench_function("cred_issue", |b| {
        b.iter(|| {
            // 测试 cred_issue 性能
            black_box(cred_issue(&params, &issuer_kp.sk, msg, attributes, tag));
        });
    });
}

// 测试 cred_verify 函数的性能
fn bench_cred_verify(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";

    // 使用 params.g1 替代 G1::generator()
    let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();

    c.bench_function("cred_verify", |b| {
        b.iter(|| {
            // 测试 cred_verify 性能
            black_box(cred_verify(&params, &credential, &issuer_kp.pk));
        });
    });
}

// 测试 trace 函数的性能
fn bench_trace(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";

    // 使用 params.g1 替代 G1::generator()
    let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();

    c.bench_function("trace", |b| {
        b.iter(|| {
            // 测试 trace 性能
            black_box(trace(&credential));
        });
    });
}

// 测试 revoke 函数的性能
fn bench_revoke(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";

    // 使用 params.g1 替代 G1::generator()
    let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();

    let mut revocation_list = Vec::new();
    c.bench_function("revoke", |b| {
        b.iter(|| {
            // 测试 revoke 性能
            black_box(revoke(&credential, &mut revocation_list));
        });
    });
}

// 测试 audit 函数的性能
fn bench_audit(c: &mut Criterion) {
    let mut logs = Vec::new();
    for i in 0..10 {
        let params = SystemParams::setup();
        let issuer_kp = IssuerKeyPair::generate(&params);
        let msg = b"Test message for credential";
        let attributes = b"User attributes data";

        // 使用 params.g1 替代 G1::generator()
        let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

        let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
        let log = PaymentLog {
            receipt: pre_payment(&params, &credential, 100).unwrap(),
            location: if i % 2 == 0 { "A停车场".to_string() } else { "B停车场".to_string() },
            user_hash: trace(&credential),
        };
        logs.push(log);
    }

    c.bench_function("audit", |b| {
        b.iter(|| {
            // 测试 audit 性能
            black_box(audit(&logs));
        });
    });
}

// 测试 fee_deduct 函数的性能
fn bench_fee_deduct(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";

    // 使用 params.g1 替代 G1::generator()
    let tag = params.g1;  // 这里我们使用 SystemParams 中的 g1

    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
    let receipt = crate::pre_payment(&params, &credential, 100).unwrap();

    c.bench_function("fee_deduct", |b| {
        b.iter(|| {
            // 测试 fee_deduct 性能
            black_box(fee_deduct(&params, &receipt));
        });
    });
}

// 将所有基准测试组合到一起
criterion_group!(
    name = new_benches;
    config = Criterion::default().sample_size(100);
    targets =
    bench_system_params_setup,
    bench_issuer_keypair_generate,
    bench_verifier_keypair_generate,
    bench_schnorr_sign,
    bench_schnorr_verify,
    bench_cred_issue,
    bench_cred_verify,
    bench_trace,
    bench_revoke,
    bench_audit,
    bench_fee_deduct
);

criterion_main!(new_benches);
