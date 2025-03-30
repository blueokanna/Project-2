use std::collections::VecDeque;
use ark_ec::{CurveGroup, PrimeGroup};
use log::{error, info, LevelFilter};
use rand::thread_rng;
use HuangProject2::{audit, blind_sign_message, cred_issue, cred_update, cred_verify, dual_issuer_sign, fee_deduct, group_sign, pre_payment, revoke, time_bound_verify, trace, CryptoError, GroupManager, IssuerKeyPair, PaymentLog, PaymentSystem, SystemParams, VerifierKeyPair};
use ark_bls12_381::{Fr as ScalarField, G1Projective as G1};
use ark_ff::{PrimeField, UniformRand};

// ======================================================================
// 主函数：展示系统全流程（凭证操作、支付、审计、撤销与双花检测）
// ======================================================================
fn main() -> Result<(), CryptoError> {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    // 系统参数初始化（预计算生成元）
    let params = SystemParams::setup();
    info!("系统参数已设置。");

    // 密钥对生成
    let issuer_kp1 = IssuerKeyPair::generate(&params); // 发行者1密钥对
    let issuer_kp2 = IssuerKeyPair::generate(&params); // 发行者2密钥对
    info!("发行者1密钥对生成完成：公钥 {:?}", issuer_kp1.pk);
    info!("发行者2密钥对生成完成：公钥 {:?}", issuer_kp2.pk);

    let verifier_kp = VerifierKeyPair::generate(&params);
    info!("验证者密钥对生成完成：公钥 {:?}", verifier_kp.pk);

    // 新增群管理，注册群成员
    let gm = GroupManager::new(&params);
    let member_cert = gm.issue_certificate(&params, b"unique_member_id");
    info!("群成员证书生成完成：证书 {:?}", member_cert.cert);

    // 凭证签发
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";
    let mut rng = thread_rng();
    let tag = G1::from(params.g1)
        .mul_bigint(ScalarField::rand(&mut rng).into_bigint())
        .into_affine();
    info!("凭证标签生成完成。");

    // 生成凭证
    let credential = cred_issue(&params, &issuer_kp1.sk, msg, attributes, tag)?;
    info!("凭证已签发，时间戳：{}", credential.timestamp);

    // 执行盲签名
    let blinding_factor = ScalarField::rand(&mut rng);
    // 调用时传入盲因子
    let (blind_r_bytes, blind_signature) =
        blind_sign_message(&params, &issuer_kp1.sk.expose(), msg, &blinding_factor);
    info!(
    "盲签名生成成功：盲因子：{:?}, 签名：{:?}",
    blind_r_bytes, blind_signature
);

    // 执行群签名（隐藏发行者身份，通过群成员证书追溯真实签名者）
    let group_signature = group_sign(&params, &issuer_kp1.sk.expose(), msg, &member_cert, &gm.gm_pk)?;
    info!("群签名生成成功：签名：{:?}", group_signature);

    // 执行双发行者联合签名
    let dual_signature = dual_issuer_sign(&params, &issuer_kp1.sk.expose(), &issuer_kp2.sk.expose(), msg);
    info!("双发行者联合签名生成成功：签名：{:?}", dual_signature);

    // 凭证验证
    match cred_verify(&params, &credential, &issuer_kp1.pk) {
        Ok(_) => info!("凭证验证成功。"),
        Err(e) => error!("凭证验证失败：{}", e),
    }

    // 凭证更新
    let updated_credential = cred_update(&params, &issuer_kp1.sk, &credential)?;
    info!("更新后凭证时间戳：{}", updated_credential.timestamp);

    // 时间窗口验证
    let valid_timestamp = time_bound_verify(&credential, 60);
    info!("凭证时间窗口验证：{}", valid_timestamp);

    // 支付凭证生成
    let payment_receipt = pre_payment(&params, &credential, 100)?;
    let payment_receipt_clone = payment_receipt.clone();
    info!(
        "支付凭证已生成，支付承诺：{:?}",
        hex::encode(payment_receipt_clone.payment_commit)
    );

    // 支付费用扣除验证
    match fee_deduct(&params, &payment_receipt) {
        Ok(ack) => info!("费用扣除验证成功：{}", ack),
        Err(e) => error!("费用扣除验证失败：{}", e),
    }

    // 用户追踪
    let user_id = trace(&credential);
    info!("追踪到的用户 ID: {:?}", hex::encode(user_id));

    // 撤销凭证
    let mut revocation_list = VecDeque::new();
    revoke(&credential, &mut revocation_list)?;
    info!("凭证已撤销，撤销列表大小：{}", revocation_list.len());

    // 模拟支付日志并审计
    let mut logs: Vec<PaymentLog> = Vec::new();
    for i in 0..10 {
        let mut receipt = pre_payment(&params, &credential, 100 + i)?;
        receipt.timestamp += i * 3600; // 模拟时间差
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
    let report = audit(&logs);
    info!("审计报告：\n{}", report);

    // 支付系统双花检测
    let payment_system = PaymentSystem::new(params.clone());
    payment_system.verify_payment(&payment_receipt.payment_commit)?;

    Ok(())
}
