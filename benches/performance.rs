use HuangProject2::{GroupManager, IssuerKeyPair, PaymentLog, SystemParams, VerifierKeyPair, audit, blind_sign_message, cred_issue, cred_verify, dual_issuer_sign, fee_deduct, group_sign, pre_payment, revoke, schnorr_sign, schnorr_verify, trace, SchnorrSignature, CryptoError};
use ark_bls12_381::{fr, Fr, G1Affine};
use ark_ff::{UniformRand, Zero};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rand::thread_rng;
use std::collections::VecDeque;
use log::error;

// 测试 SystemParams::setup 函数的性能
fn bench_system_params_setup(c: &mut Criterion) {
    c.bench_function("SystemParams::setup", |b| {
        b.iter(|| {
            black_box(SystemParams::setup());
        });
    });
}

// 测试 IssuerKeyPair::generate 函数的性能
fn bench_issuer_keypair_generate(c: &mut Criterion) {
    let params = SystemParams::setup();
    c.bench_function("IssuerKeyPair::generate", |b| {
        b.iter(|| {
            black_box(IssuerKeyPair::generate(&params));
        });
    });
}

// 测试 VerifierKeyPair::generate 函数的性能
fn bench_verifier_keypair_generate(c: &mut Criterion) {
    let params = SystemParams::setup();
    c.bench_function("VerifierKeyPair::generate", |b| {
        b.iter(|| {
            black_box(VerifierKeyPair::generate(&params));
        });
    });
}

// 测试 schnorr_sign 函数的性能
fn bench_schnorr_sign(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for schnorr_sign";
    c.bench_function("schnorr_sign", |b| {
        b.iter(|| {
            black_box(schnorr_sign(&params, &issuer_kp.sk.expose(), msg));
        });
    });
}

// 测试 schnorr_verify 函数的性能
fn bench_schnorr_verify(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for schnorr_sign";
    let sig = schnorr_sign(&params, &issuer_kp.sk.expose(), msg);
    c.bench_function("schnorr_verify", |b| {
        b.iter(|| {
            black_box(schnorr_verify(&params, msg, &sig, &issuer_kp.pk)).expect("Verify failed");
        });
    });
}

// 测试 cred_issue 函数的性能
fn bench_cred_issue(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for credential";
    let attributes = b"User Performance attributes data";
    let tag = params.g1;
    c.bench_function("cred_issue", |b| {
        b.iter(|| {
            black_box(cred_issue(&params, &issuer_kp.sk, msg, attributes, tag));
        });
    });
}

// 测试 cred_verify 函数的性能
fn bench_cred_verify(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for credential";
    let attributes = b"User Performance attributes data";
    let tag = params.g1;
    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
    c.bench_function("cred_verify", |b| {
        b.iter(|| {
            black_box(cred_verify(&params, &credential, &issuer_kp.pk));
        });
    });
}

// 测试 trace 函数的性能
fn bench_trace(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for credential";
    let attributes = b"User Performance attributes data";
    let tag = params.g1;
    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
    c.bench_function("trace", |b| {
        b.iter(|| {
            black_box(trace(&credential));
        });
    });
}

// 测试 revoke 函数的性能
fn bench_revoke(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for credential";
    let attributes = b"User Performance attributes data";
    let tag = params.g1;
    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
    let mut revocation_list = VecDeque::with_capacity(10000);
    c.bench_function("revoke", |b| {
        b.iter(|| {
            black_box(revoke(&credential, &mut revocation_list)).expect("Revoke failed");
        });
    });
}

// 测试 audit 函数的性能
fn bench_audit(c: &mut Criterion) {
    let mut logs = Vec::new();
    for i in 0..10 {
        let params = SystemParams::setup();
        let issuer_kp = IssuerKeyPair::generate(&params);
        let msg = b"Performance Test message for credential";
        let attributes = b"User Performance attributes data";
        let tag = params.g1;
        let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
        let receipt = pre_payment(&params, &credential, 100).unwrap();
        let log = PaymentLog {
            receipt,
            location: if i % 2 == 0 {
                "A停车场".to_string()
            } else {
                "B停车场".to_string()
            },
            user_hash: trace(&credential),
        };
        logs.push(log);
    }
    c.bench_function("audit", |b| {
        b.iter(|| {
            black_box(audit(&logs));
        });
    });
}

// 测试 fee_deduct 函数的性能
fn bench_fee_deduct(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for credential";
    let attributes = b"User Performance attributes data";
    let tag = params.g1;
    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag).unwrap();
    let receipt = pre_payment(&params, &credential, 100).unwrap();
    c.bench_function("fee_deduct", |b| {
        b.iter(|| {
            black_box(fee_deduct(&params, &receipt));
        });
    });
}

// 测试 blind_sign_message 函数的性能
fn bench_blind_sign_message(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for blind_sign";
    let mut rng = thread_rng();
    let blinding_factor = Fr::rand(&mut rng);
    c.bench_function("blind_sign_message", |b| {
        b.iter(|| {
            black_box(blind_sign_message(
                &params,
                &issuer_kp.sk.expose(),
                msg,
                &blinding_factor,
            ));
        });
    });
}

// 测试 group_sign 函数的性能
fn bench_group_sign(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp = IssuerKeyPair::generate(&params);

    let msg = b"Performance Test message for group_sign";
    let gm = GroupManager::new(&params);
    let member_cert = gm.issue_certificate(&params, b"unique_member_id");

    c.bench_function("group_sign", |b| {
        b.iter(|| {
            match group_sign(&params, &issuer_kp.sk.expose(), msg, &member_cert, &issuer_kp.pk) {
                Ok(sig) => black_box(sig),  // 如果签名成功，继续执行
                Err(e) => {
                    eprintln!("Error during group_sign: {:?}", e); // 打印错误信息
                    // 返回一个默认值或者一个应急签名对象来避免类型不匹配
                    // 这里使用一个默认值，你可以选择其他的错误处理策略
                    return black_box(SchnorrSignature {
                        r: G1Affine::identity(),  // 返回一个空的 r
                        s: Fr::zero(),    // 返回零的 s
                        ts: 0,                     // 时间戳设置为 0
                    });
                },
            }
        });
    });
}



// 测试 dual_issuer_sign 函数的性能
fn bench_dual_issuer_sign(c: &mut Criterion) {
    let params = SystemParams::setup();
    let issuer_kp1 = IssuerKeyPair::generate(&params);
    let issuer_kp2 = IssuerKeyPair::generate(&params);
    let msg = b"Performance Test message for dual_issuer_sign";
    c.bench_function("dual_issuer_sign", |b| {
        b.iter(|| {
            black_box(dual_issuer_sign(
                &params,
                &issuer_kp1.sk.expose(),
                &issuer_kp2.sk.expose(),
                msg,
            ));
        });
    });
}

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
        bench_fee_deduct,
        bench_blind_sign_message,
        bench_group_sign,
        bench_dual_issuer_sign
);

criterion_main!(new_benches);
