use ark_bls12_381::{Bls12_381, Fr as ScalarField, G1Projective as G1, G2Projective as G2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake3;
use rand::thread_rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::ops::{Add, AddAssign};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ======================================================================
// 辅助序列化函数（压缩序列化，降低内存消耗）
// ======================================================================

fn serialize_affine<S, A>(affine: &A, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    A: CanonicalSerialize,
{
    let mut bytes = Vec::with_capacity(64);
    affine
        .serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

fn deserialize_affine<'de, D, A>(deserializer: D) -> Result<A, D::Error>
where
    D: Deserializer<'de>,
    A: CanonicalDeserialize,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    A::deserialize_compressed(&*bytes).map_err(serde::de::Error::custom)
}

fn serialize_g1_affine<S>(
    affine: &<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_affine(affine, serializer)
}

fn deserialize_g1_affine<'de, D>(
    deserializer: D,
) -> Result<<Bls12_381 as ark_ec::pairing::Pairing>::G1Affine, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_affine(deserializer)
}

fn serialize_g2_affine<S>(
    affine: &<Bls12_381 as ark_ec::pairing::Pairing>::G2Affine,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_affine(affine, serializer)
}

fn deserialize_g2_affine<'de, D>(
    deserializer: D,
) -> Result<<Bls12_381 as ark_ec::pairing::Pairing>::G2Affine, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_affine(deserializer)
}

fn serialize_scalar<S>(scalar: &ScalarField, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = scalar.into_bigint().to_bytes_be();
    serializer.serialize_bytes(&bytes)
}

fn deserialize_scalar<'de, D>(deserializer: D) -> Result<ScalarField, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    Ok(ScalarField::from_be_bytes_mod_order(&bytes))
}

// ======================================================================
// 基本类型与错误定义
// ======================================================================

#[derive(Clone, Debug)]
pub struct Secret<T>(T);
impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

pub type G1Affine = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine;
pub type G2Affine = <Bls12_381 as ark_ec::pairing::Pairing>::G2Affine;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("哈希到曲线失败")]
    HashToCurveFailure,
    #[error("签名验证失败")]
    InvalidSignature,
    #[error("双花检测")]
    DoubleSpending,
    #[error("无效的时间戳")]
    InvalidTime,
    #[error("系统时间错误")]
    SystemTimeError,
    #[error("内部锁错误")]
    InternalLockError,
}

// ======================================================================
// 系统参数及密钥生成
// ======================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemParams {
    #[serde(serialize_with = "serialize_g1_affine", deserialize_with = "deserialize_g1_affine")]
    pub g1: G1Affine,
    #[serde(serialize_with = "serialize_g2_affine", deserialize_with = "deserialize_g2_affine")]
    pub g2: G2Affine,
    /// 域分离常量，用于哈希到 G1
    pub h1_domain: Vec<u8>,
    /// 域分离常量，用于哈希到标量
    pub h2_domain: Vec<u8>,
}

impl SystemParams {
    pub fn setup() -> Self {
        let g1 = G1::generator().into_affine();
        let g2 = G2::generator().into_affine();
        Self {
            g1,
            g2,
            h1_domain: b"JNU_H1_DOMAIN".to_vec(),
            h2_domain: b"JNU_H2_DOMAIN".to_vec(),
        }
    }
}

/// 发行者密钥对：私钥不直接暴露
#[derive(Clone, Debug)]
pub struct IssuerKeyPair {
    pub sk: Secret<ScalarField>,
    /// 公钥：pk_sig = g1^sk
    pub pk: G1Affine,
}

impl IssuerKeyPair {
    pub fn generate(params: &SystemParams) -> Self {
        let mut rng = thread_rng();
        let sk = ScalarField::rand(&mut rng);
        let pk = G1::from(params.g1).mul_bigint(sk.into_bigint()).into_affine();
        Self {
            sk: Secret::new(sk),
            pk,
        }
    }
}

/// 验证者（如停车场）密钥对
#[derive(Clone, Debug)]
pub struct VerifierKeyPair {
    pub sk: Secret<ScalarField>,
    pub pk: G1Affine,
}

impl VerifierKeyPair {
    pub fn generate(params: &SystemParams) -> Self {
        let mut rng = thread_rng();
        let sk = ScalarField::rand(&mut rng);
        let pk = G1::from(params.g1).mul_bigint(sk.into_bigint()).into_affine();
        Self {
            sk: Secret::new(sk),
            pk,
        }
    }
}

// ======================================================================
// 哈希辅助函数（标准化哈希到标量与哈希到曲线）
// ======================================================================

pub fn hash_to_scalar(domain: &[u8], data: &[u8]) -> ScalarField {
    let mut ctx = blake3::Hasher::new();
    ctx.update(domain);
    ctx.update(data);
    let hash = ctx.finalize();
    ScalarField::from_be_bytes_mod_order(hash.as_bytes())
}

pub fn hash_to_g1(params: &SystemParams, data: &[u8]) -> G1 {
    let scalar = hash_to_scalar(&params.h1_domain, data);
    G1::from(params.g1).mul_bigint(scalar.into_bigint())
}

// ======================================================================
// Schnorr 签名实现（采用高效方案，避免配对运算）
// ======================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrSignature {
    #[serde(serialize_with = "serialize_g1_affine", deserialize_with = "deserialize_g1_affine")]
    pub R: G1Affine,
    #[serde(serialize_with = "serialize_scalar", deserialize_with = "deserialize_scalar")]
    pub s: ScalarField,
}

pub fn schnorr_sign(
    params: &SystemParams,
    issuer_sk: &ScalarField,
    msg_bytes: &[u8],
) -> SchnorrSignature {
    let mut rng = thread_rng();
    let k = ScalarField::rand(&mut rng);
    let R = G1::from(params.g1).mul_bigint(k.into_bigint()).into_affine();
    let mut data = Vec::with_capacity(128);
    {
        let mut buf = Vec::with_capacity(64);
        R.serialize_compressed(&mut buf).expect("R 序列化应成功");
        data.extend_from_slice(&buf);
    }
    data.extend_from_slice(msg_bytes);
    let c = hash_to_scalar(&params.h2_domain, &data);
    let mut s = k;
    s.add_assign(&(*issuer_sk * c));
    SchnorrSignature { R, s }
}

pub fn schnorr_verify(
    params: &SystemParams,
    msg_bytes: &[u8],
    sig: &SchnorrSignature,
    pk: &G1Affine,
) -> Result<(), CryptoError> {
    let mut data = Vec::with_capacity(128);
    {
        let mut buf = Vec::with_capacity(64);
        sig.R
            .serialize_compressed(&mut buf)
            .map_err(|_| CryptoError::InvalidSignature)?;
        data.extend_from_slice(&buf);
    }
    data.extend_from_slice(msg_bytes);
    let c = hash_to_scalar(&params.h2_domain, &data);
    let gs = G1::from(params.g1).mul_bigint(sig.s.into_bigint());
    let pkc = G1::from(*pk).mul_bigint(c.into_bigint());
    let rhs = G1::from(sig.R).add(&pkc);
    if gs.into_affine() == rhs.into_affine() {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

// ======================================================================
// 凭证相关算法（签发、验证、更新），确保不可关联和抗时间篡改
// ======================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub msg: Vec<u8>,
    pub attributes: Vec<u8>,
    #[serde(serialize_with = "serialize_g1_affine", deserialize_with = "deserialize_g1_affine")]
    pub tag: G1Affine,
    pub signature: SchnorrSignature,
    pub timestamp: u64,
}

fn get_current_timestamp() -> Result<u64, CryptoError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::SystemTimeError)
        .map(|d| d.as_secs())
}

pub fn cred_issue(
    params: &SystemParams,
    issuer_sk: &Secret<ScalarField>,
    msg: &[u8],
    attributes: &[u8],
    tag: G1Affine,
) -> Result<Credential, CryptoError> {
    let timestamp = get_current_timestamp()?;
    let mut data = Vec::with_capacity(msg.len() + attributes.len() + 64);
    data.extend_from_slice(msg);
    data.extend_from_slice(attributes);
    {
        let mut buf = Vec::with_capacity(64);
        tag.serialize_compressed(&mut buf)
            .map_err(|_| CryptoError::InvalidSignature)?;
        data.extend_from_slice(&buf);
    }
    data.extend_from_slice(&timestamp.to_be_bytes());
    let signature = schnorr_sign(params, issuer_sk.expose_secret(), &data);
    Ok(Credential {
        msg: msg.to_vec(),
        attributes: attributes.to_vec(),
        tag,
        signature,
        timestamp,
    })
}

pub fn cred_verify(
    params: &SystemParams,
    cred: &Credential,
    pk: &G1Affine,
) -> Result<(), CryptoError> {
    let mut data = Vec::with_capacity(cred.msg.len() + cred.attributes.len() + 64);
    data.extend_from_slice(&cred.msg);
    data.extend_from_slice(&cred.attributes);
    {
        let mut buf = Vec::with_capacity(64);
        cred.tag
            .serialize_compressed(&mut buf)
            .map_err(|_| CryptoError::InvalidSignature)?;
        data.extend_from_slice(&buf);
    }
    data.extend_from_slice(&cred.timestamp.to_be_bytes());
    schnorr_verify(params, &data, &cred.signature, pk)
}

pub fn cred_update(
    params: &SystemParams,
    issuer_sk: &Secret<ScalarField>,
    cred: &Credential,
) -> Result<Credential, CryptoError> {
    let new_timestamp = get_current_timestamp()?;
    let mut rng = thread_rng();
    let new_tag = G1::from(params.g1)
        .mul_bigint(ScalarField::rand(&mut rng).into_bigint())
        .into_affine();
    let mut data = Vec::with_capacity(cred.msg.len() + cred.attributes.len() + 64);
    data.extend_from_slice(&cred.msg);
    data.extend_from_slice(&cred.attributes);
    {
        let mut buf = Vec::with_capacity(64);
        new_tag.serialize_compressed(&mut buf)
            .map_err(|_| CryptoError::InvalidSignature)?;
        data.extend_from_slice(&buf);
    }
    data.extend_from_slice(&new_timestamp.to_be_bytes());
    let signature = schnorr_sign(params, issuer_sk.expose_secret(), &data);
    Ok(Credential {
        msg: cred.msg.clone(),
        attributes: cred.attributes.clone(),
        tag: new_tag,
        signature,
        timestamp: new_timestamp,
    })
}

pub fn time_bound_verify(cred: &Credential, window_secs: u64) -> bool {
    match get_current_timestamp() {
        Ok(current) => current <= cred.timestamp + window_secs,
        Err(_) => false,
    }
}

// ======================================================================
// 支付及附加算法（支付、验证、违规追踪、撤销）
// ======================================================================

pub struct PaymentSystem {
    params: SystemParams,
    spent_commitments: Mutex<HashSet<Vec<u8>>>,
}

impl PaymentSystem {
    pub fn new(params: SystemParams) -> Self {
        Self {
            params,
            spent_commitments: Mutex::new(HashSet::new()),
        }
    }

    pub fn verify_payment(&self, commit: &[u8]) -> Result<(), CryptoError> {
        let mut spent = self
            .spent_commitments
            .lock()
            .map_err(|_| CryptoError::InternalLockError)?;
        if spent.contains(commit) {
            Err(CryptoError::DoubleSpending)
        } else {
            spent.insert(commit.to_vec());
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    #[serde(serialize_with = "serialize_g1_affine", deserialize_with = "deserialize_g1_affine")]
    pub cred_tag: G1Affine,
    pub fee: u64,
    pub timestamp: u64,
    pub payment_commit: Vec<u8>,
}

/// 停车支付：生成新的支付标签和支付承诺，签名数据中包含时间戳确保抗重放
pub fn pre_payment(
    params: &SystemParams,
    cred: &Credential,
    fee: u64,
) -> Result<PaymentReceipt, CryptoError> {
    let timestamp = get_current_timestamp()?;
    let mut rng = thread_rng();
    let r_p = ScalarField::rand(&mut rng);
    let tag_rp = G1::from(params.g1).mul_bigint(r_p.into_bigint());
    let tag_p = G1::from(cred.tag).add(&tag_rp).into_affine();
    let mut data = Vec::with_capacity(128);
    {
        let mut buf = Vec::with_capacity(64);
        cred.tag
            .serialize_compressed(&mut buf)
            .map_err(|_| CryptoError::InvalidSignature)?;
        data.extend_from_slice(&buf);
    }
    {
        let mut buf = Vec::with_capacity(64);
        tag_p
            .serialize_compressed(&mut buf)
            .map_err(|_| CryptoError::InvalidSignature)?;
        data.extend_from_slice(&buf);
    }
    data.extend_from_slice(&timestamp.to_be_bytes());
    let commit_scalar = hash_to_scalar(&params.h2_domain, &data);
    let commit_bytes = commit_scalar.into_bigint().to_bytes_be();
    Ok(PaymentReceipt {
        cred_tag: cred.tag,
        fee,
        timestamp,
        payment_commit: commit_bytes,
    })
}

pub fn fee_deduct(
    _params: &SystemParams,
    receipt: &PaymentReceipt,
) -> Result<bool, CryptoError> {
    if get_current_timestamp()? <= receipt.timestamp + 300 {
        Ok(true)
    } else {
        Err(CryptoError::InvalidTime)
    }
}

pub fn trace(cred: &Credential) -> Vec<u8> {
    let mut data = Vec::with_capacity(cred.msg.len() + cred.attributes.len());
    data.extend_from_slice(&cred.msg);
    data.extend_from_slice(&cred.attributes);
    let hash = blake3::hash(&data);
    hash.as_bytes().to_vec()
}

pub fn revoke(cred: &Credential, revocation_list: &mut Vec<G1Affine>) -> Result<(), CryptoError> {
    revocation_list.push(cred.tag);
    Ok(())
}

// ======================================================================
// 审计模块：对支付日志进行匿名统计并生成详细报告
// ======================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLog {
    pub receipt: PaymentReceipt,
    /// 停车场标识（例如停车场 ID 或位置）
    pub location: String,
    /// 匿名用户标识（经过哈希处理）
    pub user_hash: Vec<u8>,
}

/// 审计函数：统计总交易数、每日收入、各停车场利用率和用户支付频率，生成详细报告
pub fn audit(logs: &[PaymentLog]) -> String {
    let total_payments = logs.len();
    let mut daily_revenue: HashMap<u64, u64> = HashMap::new();
    let mut parking_usage: HashMap<&str, u64> = HashMap::new();
    let mut user_payment_freq: HashMap<Vec<u8>, u64> = HashMap::new();

    for log in logs {
        // 按天统计：将时间戳除以 86400 得到天编号
        let day = log.receipt.timestamp / 86400;
        *daily_revenue.entry(day).or_insert(0) += log.receipt.fee;

        // 停车场利用率
        *parking_usage.entry(log.location.as_str()).or_insert(0) += 1;

        // 用户支付频率
        *user_payment_freq.entry(log.user_hash.clone()).or_insert(0) += 1;
    }

    // 构造报告字符串
    let mut report = String::new();
    use std::fmt::Write;
    writeln!(report, "=== 审计报告 ===").unwrap();
    writeln!(report, "总支付交易数：{}", total_payments).unwrap();
    writeln!(report, "\n每日总收入：").unwrap();
    let mut daily: Vec<_> = daily_revenue.into_iter().collect();
    daily.sort_by_key(|&(day, _)| day);
    for (day, revenue) in daily {
        writeln!(report, "  日编号 {}： 收入 {}", day, revenue).unwrap();
    }
    writeln!(report, "\n各停车场利用率：").unwrap();
    for (location, count) in parking_usage {
        writeln!(report, "  {}： {} 次", location, count).unwrap();
    }
    writeln!(report, "\n用户支付频率（匿名）：").unwrap();
    for (user, freq) in user_payment_freq {
        writeln!(report, "  用户 {}： {} 次", hex::encode(user), freq).unwrap();
    }
    report
}

// ======================================================================
// 主函数：展示系统全流程，包括凭证操作、支付和审计
// ======================================================================

fn main() -> Result<(), CryptoError> {
    // === 系统参数设置 ===
    // 初始化系统参数，包括生成 G1 和 G2 的生成元，以及域分离常量
    let params = SystemParams::setup();
    println!("系统参数已设置。");

    // === 密钥对生成 ===
    // 生成发行者密钥对（包括私钥和公钥），公钥是 G1^sk
    let issuer_kp = IssuerKeyPair::generate(&params);
    println!(
        "发行者密钥对生成完成：公钥 {:?}",
        issuer_kp.pk
    );

    // 生成验证者密钥对（包括私钥和公钥），用于验证签名
    let verifier_kp = VerifierKeyPair::generate(&params);
    println!(
        "验证者密钥对生成完成：公钥 {:?}",
        verifier_kp.pk
    );

    // === 凭证签发 ===
    // 创建一条凭证消息（msg）和一些附加属性（attributes）
    let msg = b"Test message for credential";
    let attributes = b"User attributes data";

    // 生成凭证标签（tag）——它是一个随机生成的 G1 元素
    let mut rng = thread_rng();
    let tag = G1::from(params.g1)
        .mul_bigint(ScalarField::rand(&mut rng).into_bigint())
        .into_affine();
    println!("凭证标签生成完成。");

    // 使用发行者的私钥（sk）签发凭证
    let credential = cred_issue(&params, &issuer_kp.sk, msg, attributes, tag)?;
    println!(
        "凭证已签发，时间戳：{}",
        credential.timestamp
    );

    // === 凭证验证 ===
    // 验证凭证的签名是否有效
    match cred_verify(&params, &credential, &issuer_kp.pk) {
        Ok(_) => println!("凭证验证成功。"),
        Err(e) => println!("凭证验证失败：{}", e),
    }

    // === 凭证更新 ===
    // 更新凭证的标签并重新签发
    let updated_credential = cred_update(&params, &issuer_kp.sk, &credential)?;
    println!(
        "更新后的凭证时间戳：{}",
        updated_credential.timestamp
    );

    // === 时间有效性验证 ===
    // 检查凭证是否在给定的时间窗口内有效
    let valid_timestamp = time_bound_verify(&credential, 60);
    println!("凭证时间窗口验证：{}", valid_timestamp);

    // === 支付凭证生成 ===
    // 进行停车支付，生成支付凭证
    let payment_receipt = pre_payment(&params, &credential, 100)?;
    println!(
        "支付凭证已生成，支付承诺：{:02x?}",
        payment_receipt.payment_commit
    );

    // === 支付费用扣除验证 ===
    // 验证支付费用是否在有效时间内
    match fee_deduct(&params, &payment_receipt) {
        Ok(ack) => println!("费用扣除验证成功：{}", ack),
        Err(e) => println!("费用扣除验证失败：{}", e),
    }

    // === 用户追踪 ===
    // 通过凭证追踪用户的匿名标识
    let user_id = trace(&credential);
    println!("追踪到的用户 ID: {:02x?}", user_id);

    // === 撤销凭证 ===
    // 将凭证加入撤销列表
    let mut revocation_list: Vec<G1Affine> = Vec::new();
    revoke(&credential, &mut revocation_list)?;
    println!(
        "凭证已撤销，撤销列表大小：{}",
        revocation_list.len()
    );

    // === 审计系统 ===
    // 模拟多笔支付记录并进行审计
    let mut logs: Vec<PaymentLog> = Vec::new();
    for i in 0..10 {
        // 模拟不同时间、不同停车场和不同用户
        let mut receipt = pre_payment(&params, &credential, 100 + i)?;
        // 令时间戳递增
        receipt.timestamp += i * 3600;

        // 模拟不同停车场与用户
        let log = PaymentLog {
            receipt,
            location: if i % 2 == 0 { "A停车场".to_string() } else { "B停车场".to_string() },
            user_hash: trace(&credential),
        };
        logs.push(log);
    }

    // 审计并生成报告
    let report = audit(&logs);
    println!("审计报告：\n{}", report);

    // === 支付系统双花检测 ===
    // 检查支付承诺是否已经被使用过，避免双花
    let payment_system = PaymentSystem::new(params.clone());
    payment_system.verify_payment(&payment_receipt.payment_commit)?;

    Ok(())
}
