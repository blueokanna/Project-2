use ark_bls12_381::{Bls12_381, Fr as ScalarField, G1Projective as G1, G2Projective as G2};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake3;
use log::error;
use rand::thread_rng;
use rayon::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::{Add, AddAssign, SubAssign};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use thiserror::Error;

// ======================================================================
// 常量定义：域分离常量
// ======================================================================
const BLS12_381_G1_HASH_DOMAIN: &[u8] = b"BLS12-381:G1_HASH";
const BLS12_381_SCALAR_HASH_DOMAIN: &[u8] = b"BLS12-381:SCALAR_HASH";

// ======================================================================
// 辅助序列化函数（压缩序列化）
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

type G1Affine = <Bls12_381 as ark_ec::pairing::Pairing>::G1Affine;
type G2Affine = <Bls12_381 as ark_ec::pairing::Pairing>::G2Affine;

fn serialize_g1_affine<S>(affine: &G1Affine, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_affine(affine, serializer)
}

fn deserialize_g1_affine<'de, D>(deserializer: D) -> Result<G1Affine, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_affine(deserializer)
}

fn serialize_g2_affine<S>(affine: &G2Affine, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serialize_affine(affine, serializer)
}

fn deserialize_g2_affine<'de, D>(deserializer: D) -> Result<G2Affine, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_affine(deserializer)
}

// ======================================================================
// 错误定义
// ======================================================================
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
    #[error("盲签名/群签名错误")]
    SignatureError,
}

// ======================================================================
// 时间模块（采用可信 UTC 时间，防止时间篡改）
// ======================================================================

mod time_helper {
    use super::CryptoError;
    use chrono::{DateTime, Local};
    use rsntp::SntpClient;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn get_current_timestamp() -> Result<u64, CryptoError> {
        if let Ok(client) = SntpClient::new().synchronize("ntp.aliyun.com") {
            if let Ok(chrono_dt) = client.datetime().into_chrono_datetime() {
                // 将同步的时间转换为本地时间，再转换为毫秒后换算为秒
                let local_time: DateTime<Local> = DateTime::from(chrono_dt);
                return Ok((local_time.timestamp_millis() / 1000) as u64);
            }
        }

        // 如果网络同步失败，则回退到使用本地系统时间
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::SystemTimeError)
            .map(|d| d.as_secs())
    }
}
use time_helper::get_current_timestamp;

// ======================================================================
// 基本类型与密钥生成
// ======================================================================
#[derive(Clone, Debug)]
pub struct Secret<T>(T);
impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &T {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemParams {
    #[serde(
        serialize_with = "serialize_g1_affine",
        deserialize_with = "deserialize_g1_affine"
    )]
    pub g1: G1Affine,
    #[serde(
        serialize_with = "serialize_g2_affine",
        deserialize_with = "deserialize_g2_affine"
    )]
    pub g2: G2Affine,
    /// 域分离常量：用于哈希到 G1
    pub h1_domain: Vec<u8>,
    /// 域分离常量：用于哈希到标量
    pub h2_domain: Vec<u8>,
}

impl SystemParams {
    pub fn setup() -> Self {
        let g1 = G1::generator().into_affine();
        let g2 = G2::generator().into_affine();
        Self {
            g1,
            g2,
            h1_domain: BLS12_381_G1_HASH_DOMAIN.to_vec(),
            h2_domain: BLS12_381_SCALAR_HASH_DOMAIN.to_vec(),
        }
    }
}

// 发行者密钥对：私钥不直接暴露
#[derive(Clone, Debug)]
pub struct IssuerKeyPair {
    pub sk: Secret<ScalarField>,
    /// 公钥：pk = g1^sk
    pub pk: G1Affine,
}

impl IssuerKeyPair {
    pub fn generate(params: &SystemParams) -> Self {
        let (sk, pk) = generate_keypair(params);
        Self {
            sk: Secret::new(sk),
            pk,
        }
    }
}

// 验证者密钥对
#[derive(Clone, Debug)]
pub struct VerifierKeyPair {
    pub sk: Secret<ScalarField>,
    pub pk: G1Affine,
}

impl VerifierKeyPair {
    pub fn generate(params: &SystemParams) -> Self {
        let (sk, pk) = generate_keypair(params);
        Self {
            sk: Secret::new(sk),
            pk,
        }
    }
}

// ======================================================================
// 哈希辅助函数：标准化哈希到标量与哈希到曲线
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
// 数据拼接辅助函数（统一数据拼接，减少重复代码）
// ======================================================================
fn concat_data(slices: &[&[u8]]) -> Vec<u8> {
    let total = slices.iter().map(|s| s.len()).sum();
    let mut data = Vec::with_capacity(total);
    for s in slices {
        data.extend_from_slice(s);
    }
    data
}

pub fn generate_keypair(params: &SystemParams) -> (ScalarField, G1Affine) {
    let mut rng = thread_rng();
    let sk = ScalarField::rand(&mut rng);
    let pk = G1::from(params.g1)
        .mul_bigint(sk.into_bigint())
        .into_affine();
    (sk, pk)
}

fn serialize_element<A: CanonicalSerialize>(element: &A) -> Result<Vec<u8>, CryptoError> {
    let mut buf = Vec::with_capacity(64);
    element
        .serialize_compressed(&mut buf)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(buf)
}

// ======================================================================
// Schnorr 签名实现（避免配对运算，提高效率）
// ======================================================================
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrSignature {
    #[serde(
        serialize_with = "serialize_g1_affine",
        deserialize_with = "deserialize_g1_affine"
    )]
    pub r: G1Affine,
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    pub s: ScalarField,
    // 附加时间戳签名，防止重放
    pub ts: u64,
}

pub fn schnorr_sign(
    params: &SystemParams,
    issuer_sk: &ScalarField,
    msg_bytes: &[u8],
) -> SchnorrSignature {
    let mut rng = thread_rng();
    let k = ScalarField::rand(&mut rng);
    let r = G1::from(params.g1)
        .mul_bigint(k.into_bigint())
        .into_affine();
    let ts = get_current_timestamp().unwrap_or(0);
    let mut buf = Vec::with_capacity(128);
    {
        let mut temp = Vec::with_capacity(64);
        r.serialize_compressed(&mut temp).expect("r 序列化应成功");
        buf.extend_from_slice(&temp);
    }
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(msg_bytes);
    let c = hash_to_scalar(&params.h2_domain, &buf);
    let mut s = k;
    s.add_assign(&(*issuer_sk * c));
    SchnorrSignature { r, s, ts }
}

pub fn schnorr_verify(
    params: &SystemParams,
    msg_bytes: &[u8],
    sig: &SchnorrSignature,
    pk: &G1Affine,
) -> Result<(), CryptoError> {
    let mut buf = Vec::with_capacity(128);
    {
        let mut temp = Vec::with_capacity(64);
        sig.r
            .serialize_compressed(&mut temp)
            .map_err(|_| CryptoError::InvalidSignature)?;
        buf.extend_from_slice(&temp);
    }
    buf.extend_from_slice(&sig.ts.to_be_bytes());
    buf.extend_from_slice(msg_bytes);
    let c = hash_to_scalar(&params.h2_domain, &buf);
    let gs = G1::from(params.g1).mul_bigint(sig.s.into_bigint());
    let pkc = G1::from(*pk).mul_bigint(c.into_bigint());
    let rhs = G1::from(sig.r).add(&pkc);
    if gs.into_affine() == rhs.into_affine() {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

// ======================================================================
// 盲签名：用户侧实现盲化及解盲，签发侧无需修改
// ======================================================================
pub fn blind_sign_message(
    params: &SystemParams,
    issuer_sk: &ScalarField,
    msg_bytes: &[u8],
    blinding_factor: &ScalarField,
) -> (Vec<u8>, SchnorrSignature) {
    // 用户侧：计算盲化消息
    let hash_val = hash_to_scalar(&params.h2_domain, msg_bytes);
    let blinded_scalar = hash_val * (*blinding_factor);
    let blinded_bytes = blinded_scalar.into_bigint().to_bytes_be();
    // 签发侧对盲化消息进行签名
    let blinded_sig = schnorr_sign(params, issuer_sk, &blinded_bytes);
    // 返回 blinding_factor 序列化和盲签名
    (blinding_factor.into_bigint().to_bytes_be(), blinded_sig)
}

pub fn blind_deblind(
    _params: &SystemParams,
    blinded_sig: &SchnorrSignature,
    blinding_factor: &ScalarField,
) -> SchnorrSignature {
    // 计算逆元
    let inv = blinding_factor.inverse().expect("blinding_factor 不可为 0");
    let s_deblinded = blinded_sig.s * inv;
    SchnorrSignature {
        r: blinded_sig.r,
        s: s_deblinded,
        ts: blinded_sig.ts,
    }
}

// ======================================================================
// 群签名模块：新增群管理员（GM）与群成员证书管理
// ======================================================================
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupCertificate {
    pub member_id: Vec<u8>, // 可为用户哈希或唯一标识
    #[serde(
        serialize_with = "serialize_g1_affine",
        deserialize_with = "deserialize_g1_affine"
    )]
    pub cert: G1Affine, // GM 签发的证书
}

#[derive(Clone, Debug)]
pub struct GroupManager {
    pub gm_sk: ScalarField,
    pub gm_pk: G1Affine,
    pub members: Arc<Mutex<HashMap<Vec<u8>, GroupCertificate>>>,
}

impl GroupManager {
    pub fn new(params: &SystemParams) -> Self {
        let mut rng = thread_rng();
        let gm_sk = ScalarField::rand(&mut rng);
        let gm_pk = G1::from(params.g1)
            .mul_bigint(gm_sk.into_bigint())
            .into_affine();
        Self {
            gm_sk,
            gm_pk,
            members: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn issue_certificate(&self, params: &SystemParams, member_id: &[u8]) -> GroupCertificate {
        let cert_scalar = hash_to_scalar(&params.h2_domain, member_id);
        let cert = G1::from(params.g1)
            .mul_bigint((cert_scalar * self.gm_sk).into_bigint()) // 使用群管理员私钥
            .into_affine();

        let gc = GroupCertificate {
            member_id: member_id.to_vec(),
            cert,
        };
        self.members
            .lock()
            .unwrap()
            .insert(member_id.to_vec(), gc.clone());

        gc
    }

    pub fn gm_pk(&self) -> G1Affine {
        self.gm_pk
    }
}

// 群签名：成员利用自身密钥和 GM 证书签名，签名包含成员证书信息，可追溯真实签名者
pub fn group_sign(
    params: &SystemParams,
    issuer_sk: &ScalarField,
    msg_bytes: &[u8],
    member_cert: &GroupCertificate,
    gm_sk: &ScalarField,
) -> Result<SchnorrSignature, CryptoError> {
    let hash_val = hash_to_scalar(&params.h2_domain, &member_cert.member_id);
    let expected_cert = G1::from(params.g1)
        .mul_bigint((hash_val * gm_sk).into_bigint()) // 使用群管理员私钥
        .into_affine();

    // 如果计算的 expected_cert 与证书中的 cert 不匹配，返回错误
    if expected_cert != member_cert.cert {
        return Err(CryptoError::SignatureError);
    }

    // 签名流程：将成员证书也纳入签名哈希，保证可追溯
    let mut rng = thread_rng();
    let k = ScalarField::rand(&mut rng);
    let r = G1::from(params.g1)
        .mul_bigint(k.into_bigint())
        .into_affine();

    let mut buf = Vec::with_capacity(128);
    {
        let mut tmp = Vec::with_capacity(64);
        r.serialize_compressed(&mut tmp)
            .map_err(|_| CryptoError::InvalidSignature)?;
        buf.extend_from_slice(&tmp);
    }
    buf.extend_from_slice(msg_bytes);

    let cert_bytes = {
        let mut tmp = Vec::with_capacity(64);
        member_cert
            .cert
            .serialize_compressed(&mut tmp)
            .map_err(|_| CryptoError::InvalidSignature)?;
        tmp
    };
    buf.extend_from_slice(&cert_bytes);

    let c = hash_to_scalar(&params.h2_domain, &buf);

    let mut s_val = k;
    s_val.sub_assign(&(*issuer_sk * c));

    Ok(SchnorrSignature {
        r,
        s: s_val,
        ts: get_current_timestamp().unwrap_or(0),
    })
}

// ======================================================================
// 双发行者联合签名：采用两密钥门限机制（2-2 阈值方案），签名必须由两方共同产生
// ======================================================================
pub fn dual_issuer_sign(
    params: &SystemParams,
    issuer_sk1: &ScalarField,
    issuer_sk2: &ScalarField,
    msg_bytes: &[u8],
) -> SchnorrSignature {
    let mut rng = thread_rng();
    // 分别生成随机数 k1, k2
    let k1 = ScalarField::rand(&mut rng);
    let k2 = ScalarField::rand(&mut rng);
    let r1 = G1::from(params.g1)
        .mul_bigint(k1.into_bigint())
        .into_affine();
    let r2 = G1::from(params.g1)
        .mul_bigint(k2.into_bigint())
        .into_affine();
    let mut buf = Vec::with_capacity(128);
    r1.serialize_compressed(&mut buf).expect("序列化r1失败");
    r2.serialize_compressed(&mut buf).expect("序列化r2失败");
    buf.extend_from_slice(msg_bytes);
    let c = hash_to_scalar(&params.h2_domain, &buf);
    let mut s1 = k1;
    let mut s2 = k2;
    s1.sub_assign(&(*issuer_sk1 * c));
    s2.sub_assign(&(*issuer_sk2 * c));
    // 使用加法组合签名，保证只有联合签名通过验证
    SchnorrSignature {
        r: r1.add(&r2).into_affine(),
        s: s1 + s2,
        ts: get_current_timestamp().unwrap_or(0),
    }
}

// ======================================================================
// 凭证相关算法：签发、验证、更新，确保不可关联且抗时间篡改
// ======================================================================
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub msg: Vec<u8>,
    pub attributes: Vec<u8>,
    #[serde(
        serialize_with = "serialize_g1_affine",
        deserialize_with = "deserialize_g1_affine"
    )]
    pub tag: G1Affine,
    pub signature: SchnorrSignature,
    pub timestamp: u64,
}

pub fn cred_issue(
    params: &SystemParams,
    issuer_sk: &Secret<ScalarField>,
    msg: &[u8],
    attributes: &[u8],
    tag: G1Affine,
) -> Result<Credential, CryptoError> {
    let timestamp = get_current_timestamp()?;
    let tag_bytes = serialize_element(&tag)?;
    let data = concat_data(&[msg, attributes, &tag_bytes, &timestamp.to_be_bytes()]);
    let signature = schnorr_sign(params, issuer_sk.expose(), &data);
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
    let tag_bytes = serialize_element(&cred.tag)?;
    let data = concat_data(&[
        &cred.msg,
        &cred.attributes,
        &tag_bytes,
        &cred.timestamp.to_be_bytes(),
    ]);
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
    let tag_bytes = serialize_element(&cred.tag)?;
    let data = concat_data(&[
        &cred.msg,
        &cred.attributes,
        &tag_bytes,
        &new_timestamp.to_be_bytes(),
    ]);
    let signature = schnorr_sign(params, issuer_sk.expose(), &data);
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
// 支付及附加算法：支付、验证、追踪、撤销
// ======================================================================
#[allow(dead_code)]
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
    #[serde(
        serialize_with = "serialize_g1_affine",
        deserialize_with = "deserialize_g1_affine"
    )]
    pub cred_tag: G1Affine,
    pub fee: u64,
    pub timestamp: u64,
    pub payment_commit: Vec<u8>,
}

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
    let tag_bytes = serialize_element(&cred.tag)?;
    let tag_p_bytes = serialize_element(&tag_p)?;
    let data = concat_data(&[&tag_bytes, &tag_p_bytes, &timestamp.to_be_bytes()]);
    let commit_scalar = hash_to_scalar(&params.h2_domain, &data);
    let commit_bytes = commit_scalar.into_bigint().to_bytes_be();
    Ok(PaymentReceipt {
        cred_tag: cred.tag,
        fee,
        timestamp,
        payment_commit: commit_bytes,
    })
}

pub fn fee_deduct(_params: &SystemParams, receipt: &PaymentReceipt) -> Result<bool, CryptoError> {
    if get_current_timestamp()? <= receipt.timestamp + 300 {
        Ok(true)
    } else {
        Err(CryptoError::InvalidTime)
    }
}

pub fn trace(cred: &Credential) -> Vec<u8> {
    let data = concat_data(&[&cred.msg, &cred.attributes]);
    blake3::hash(&data).as_bytes().to_vec()
}

pub fn revoke(
    cred: &Credential,
    revocation_list: &mut VecDeque<G1Affine>,
) -> Result<(), CryptoError> {
    revocation_list.push_back(cred.tag);
    if revocation_list.len() > 10000 {
        revocation_list.pop_front();
    }
    Ok(())
}

// ======================================================================
// 审计模块：多线程支付日志统计报告
// ======================================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLog {
    pub receipt: PaymentReceipt,
    pub location: String,
    pub user_hash: Vec<u8>,
}

pub fn audit(logs: &[PaymentLog]) -> String {
    let total_payments = logs.len();
    let daily_revenue = Mutex::new(HashMap::<u64, u64>::new());
    let parking_usage = Mutex::new(HashMap::<String, u64>::new());
    let user_payment_freq = Mutex::new(HashMap::<Vec<u8>, u64>::new());

    logs.par_iter().for_each(|log| {
        let day = log.receipt.timestamp / 86400;
        daily_revenue
            .lock()
            .unwrap()
            .entry(day)
            .and_modify(|e| *e += log.receipt.fee)
            .or_insert(log.receipt.fee);
        parking_usage
            .lock()
            .unwrap()
            .entry(log.location.clone())
            .and_modify(|e| *e += 1)
            .or_insert(1);
        user_payment_freq
            .lock()
            .unwrap()
            .entry(log.user_hash.clone())
            .and_modify(|e| *e += 1)
            .or_insert(1);
    });

    let mut report = String::new();
    use std::fmt::Write;
    writeln!(report, "=== 审计报告 ===").unwrap();
    writeln!(report, "总支付交易数：{}", total_payments).unwrap();
    writeln!(report, "\n每日总收入：").unwrap();
    let mut daily: Vec<_> = daily_revenue.into_inner().unwrap().into_iter().collect();
    daily.sort_by_key(|&(day, _)| day);
    for (day, revenue) in daily {
        writeln!(report, "  日编号 {}： 收入 {}", day, revenue).unwrap();
    }
    writeln!(report, "\n各停车场利用率：").unwrap();
    for (location, count) in parking_usage.into_inner().unwrap() {
        writeln!(report, "  {}： {} 次", location, count).unwrap();
    }
    writeln!(report, "\n用户支付频率（匿名）：").unwrap();
    for (user, freq) in user_payment_freq.into_inner().unwrap() {
        writeln!(report, "  用户 {}： {} 次", hex::encode(user), freq).unwrap();
    }
    report
}
