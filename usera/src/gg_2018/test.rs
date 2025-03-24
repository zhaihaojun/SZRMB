#![allow(non_snake_case)]

/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

// protocols::multi_party_ecdsa::

use crate::gg_2018::party_i::{
    verify, KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, Phase5ADecom1, Phase5Com1, SharedKeys, SignKeys,
};
use crate::mta::{MessageA, MessageB};
use serde_json::{Value, from_str,to_writer};
use anyhow::{Result};
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use paillier::*;
use sha2::Sha256;

use tokio::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use std::time::{Instant, Duration};
use std::net::{TcpStream, TcpListener};
use serde_json::{to_vec, from_slice, from_value};
use std::{any, thread};
use tokio::runtime::Runtime;
use tokio::time::sleep;
use std::error::Error;
use super::party_i::{SignBroadcastPhase1, SignDecommitPhase1};
// #[cfg(test)]
use serde::{Serialize, Deserialize};
use std::fs;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use anyhow::{Context};
use tokio::sync::oneshot;

const FILE_PATH: &str = "key_data.json";

#[derive(Serialize, Deserialize, Debug)]
struct KeyData {
    party_keys_vec: Vec<Keys>,
    shared_keys_vec: Vec<SharedKeys>,
    pk_vec: Vec<Point<Secp256k1>>,
    y: Point<Secp256k1>,
    vss_scheme: VerifiableSS<Secp256k1, Sha256>,
    private_vec: Vec<PartyPrivate>,
    sign_keys_vec: Vec<SignKeys>,
}

// 保存数据到文件
fn save_key_data(data: &KeyData) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string_pretty(data)?;
    fs::write(FILE_PATH, json)?;
    Ok(())
}

// 从文件加载数据
fn load_key_data() -> Result<KeyData, anyhow::Error> {
    let json = fs::read_to_string(FILE_PATH)?;
    let data: KeyData = serde_json::from_str(&json)?;
    Ok(data)
}


// #[test]
pub fn test_keygen_t1_n2() {
    let (party_keys_vec, shared_keys_vec, pk_vec, y_sum, vss_scheme) = keygen_t_n_parties(1, 3);
    
    //打印返回的每个值
    println!("party_keys_vec: {:?}", party_keys_vec);
    println!("shared_keys_vec: {:?}", shared_keys_vec);
    println!("pk_vec: {:?}", pk_vec);
    println!("y_sum: {:?}", y_sum);
    println!("vss_scheme: {:?}", vss_scheme);
}

#[tokio::test]
pub async fn test_sign_n5_t2_ttag4() {
    // sign(1, 3, 2, vec![0, 1]);
    // keyStore();
    // TCP_TS("127.0.0.1","8084").await.unwrap();
}


pub fn keygen_t_n_parties(
    t: u16,
    n: u16,
) -> (
    Vec<Keys>,
    Vec<SharedKeys>,
    Vec<Point<Secp256k1>>,
    Point<Secp256k1>,
    VerifiableSS<Secp256k1, Sha256>,
) {
    let parames = Parameters {
        threshold: t,
        share_count: n,
    };
    let party_keys_vec = (0..n).map(Keys::create).collect::<Vec<Keys>>();

    let (bc1_vec, decom_vec): (Vec<_>, Vec<_>) = party_keys_vec
        .iter()
        .map(|k| k.phase1_broadcast_phase3_proof_of_correct_key())
        .unzip();

    let y_vec = (0..usize::from(n))
        .map(|i| decom_vec[i].y_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();

    let vss_result: Vec<_> = party_keys_vec
        .iter()
        .map(|k| {
            k.phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &decom_vec, &bc1_vec,
            )
            .expect("invalid key")
        })
        .collect();

    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares); // cannot unzip
        index_vec.push(index);
    }

    let vss_scheme_for_test = vss_scheme_vec.clone();

    let party_shares = (0..usize::from(n))
        .map(|i| {
            (0..usize::from(n))
                .map(|j| secret_shares_vec[j][i].clone())
                .collect::<Vec<Scalar<Secp256k1>>>()
        })
        .collect::<Vec<Vec<Scalar<Secp256k1>>>>();

    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = Vec::new(); // 显式声明类型
    for (i, key) in party_keys_vec.iter().enumerate() {
        let (shared_keys, dlog_proof) = key
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                (&index_vec[i] + 1),
            )
            .expect("invalid vss");
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    // 显式声明 pk_vec 的类型
    let pk_vec = dlog_proof_vec
        .iter()
        .map(|dlog_proof| dlog_proof.pk.clone())  // 访问 pk
        .collect::<Vec<Point<Secp256k1>>>();

    // both parties run:
    Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");

    // xi_vec 访问 shared_keys.x_i，确保该字段存在
    let xi_vec = shared_keys_vec
        .iter()
        .take(usize::from(t + 1))
        .map(|shared_keys| shared_keys.x_i.clone())
        .collect::<Vec<Scalar<Secp256k1>>>();

    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..=usize::from(t)], &xi_vec);
    let sum_u_i = party_keys_vec
        .iter()
        .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + &x.u_i);
    assert_eq!(x, sum_u_i);

    (
        party_keys_vec,
        shared_keys_vec,
        pk_vec,
        y_sum,
        vss_scheme_for_test[0].clone(),
    )
}

pub fn keyStore()-> Result<(), Box<dyn std::error::Error>> {
    let (mut party_keys_vec, shared_keys_vec, pk_vec, y, vss_scheme) = keygen_t_n_parties(1, 3);

        let private_vec = (0..shared_keys_vec.len())
            .map(|i| PartyPrivate::set_private(party_keys_vec[i].clone(), shared_keys_vec[i].clone()))
            .collect::<Vec<PartyPrivate>>();

        let s = vec![0, 1];
        let sign_keys_vec = (0..2)
            .map(|i| SignKeys::create(&private_vec[usize::from(s[i])], &vss_scheme, s[i], &s))
            .collect::<Vec<SignKeys>>();

        let key_data = KeyData {
            party_keys_vec,
            shared_keys_vec,
            pk_vec,
            y,
            vss_scheme,
            private_vec,
            sign_keys_vec,
        };

        // 保存数据到文件
        save_key_data(&key_data)?;
        Ok(())
}

pub fn sign(t: u16, n: u16, ttag: u16, s: Vec<u16>){
    // 清空文件，覆盖旧内容
    // let mut file = File::create("output.txt").unwrap();
    //测试 writeln!(file, "Running sign function with parameters: t={}, n={}, ttag={}, s={:?}", t, n, ttag, s).unwrap();;
    
    // full key gen emulation
    let (party_keys_vec, shared_keys_vec, _pk_vec, y, vss_scheme) = keygen_t_n_parties(t, n);

    let private_vec = (0..shared_keys_vec.len())
        .map(|i| PartyPrivate::set_private(party_keys_vec[i].clone(), shared_keys_vec[i].clone()))
        .collect::<Vec<PartyPrivate>>();
    // make sure that we have t<t'<n and the group s contains id's for t' parties
    // TODO: make sure s has unique id's and they are all in range 0..n
    // TODO: make sure this code can run when id's are not in ascending order
    assert!(ttag > t);
    let ttag = ttag as usize;
    assert_eq!(s.len(), ttag);

    // each party creates a signing key. This happens in parallel IRL. In this test we
    // create a vector of signing keys, one for each party.
    // throughout i will index parties
    let sign_keys_vec = (0..ttag)
        .map(|i| SignKeys::create(&private_vec[usize::from(s[i])], &vss_scheme, s[i], &s))
        .collect::<Vec<SignKeys>>();

    // each party computes [Ci,Di] = com(g^gamma_i) and broadcast the commitments
    let (bc1_vec, decommit_vec1): (Vec<_>, Vec<_>) =
        sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();

    // writeln!(file, "phase1-broadcast the commitments: commitment={:?}", bc1_vec[1]).unwrap();
    
    // each party i sends encryption of k_i under her Paillier key
    // m_a_vec = [ma_0;ma_1;,...]
    // range proofs are ignored here, as there's no h1, h2, N_tilde setup in this version of GG18
    let m_a_vec: Vec<_> = sign_keys_vec
        .iter()
        .enumerate()
        .map(|(i, k)| MessageA::a(&k.k_i, &party_keys_vec[usize::from(s[i])].ek, &[]).0)
        .collect();

    // each party i sends responses to m_a_vec she received (one response with input gamma_i and one with w_i)
    // m_b_gamma_vec_all is a matrix where column i is a vector of message_b's that party i answers to all ma_{j!=i} using paillier key of party j to answer to ma_j

    // aggregation of the n messages of all parties
    let mut m_b_gamma_vec_all = Vec::new();
    let mut beta_vec_all = Vec::new();
    let mut m_b_w_vec_all = Vec::new();
    let mut ni_vec_all = Vec::new();

    for (i, key) in sign_keys_vec.iter().enumerate() {
        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };

            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &key.gamma_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &key.w_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .unwrap();

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
        beta_vec_all.push(beta_vec.clone());
        m_b_w_vec_all.push(m_b_w_vec.clone());
        ni_vec_all.push(ni_vec.clone());
    }

    // Here we complete the MwA protocols by taking the mb matrices and starting with the first column generating the appropriate message
    // for example for index i=0 j=0 we need party at index s[1] to answer to mb that party s[0] sent, completing a protocol between s[0] and s[1].
    //  for index i=1 j=0 we need party at index s[0] to answer to mb that party s[1]. etc.
    // IRL each party i should get only the mb messages that other parties sent in response to the party i ma's.
    // TODO: simulate as IRL
    let mut alpha_vec_all = Vec::new();
    let mut miu_vec_all = Vec::new();

    for i in 0..ttag {
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let m_b_gamma_vec_i = &m_b_gamma_vec_all[i];
        let m_b_w_vec_i = &m_b_w_vec_all[i];

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let m_b = m_b_gamma_vec_i[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(
                    &party_keys_vec[usize::from(s[ind])].dk,
                    &sign_keys_vec[ind].k_i,
                )
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_vec_i[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(
                    &party_keys_vec[usize::from(s[ind])].dk,
                    &sign_keys_vec[ind].k_i,
                )
                .expect("wrong dlog or m_b");

            // since we actually run two MtAwc each party needs to make sure that the values B are the same as the public values
            // here for b=w_i the parties already know W_i = g^w_i  for each party so this check is done here. for b = gamma_i the check will be later when g^gamma_i will become public
            // currently we take the W_i from the other parties signing keys
            // TODO: use pk_vec (first change from x_i to w_i) for this check.
            assert_eq!(m_b.b_proof.pk, sign_keys_vec[i].g_w_i);

            alpha_vec.push(alpha_ij_gamma);
            miu_vec.push(alpha_ij_wi);
        }
        alpha_vec_all.push(alpha_vec.clone());
        miu_vec_all.push(miu_vec.clone());
    }

    let mut delta_vec = Vec::new();
    let mut sigma_vec = Vec::new();

    for i in 0..ttag {
        let alpha_vec: Vec<Scalar<Secp256k1>> = (0..alpha_vec_all[i].len())
            .map(|j| alpha_vec_all[i][j].0.clone())
            .collect();
        let miu_vec: Vec<Scalar<Secp256k1>> = (0..miu_vec_all[i].len())
            .map(|j| miu_vec_all[i][j].0.clone())
            .collect();

        let delta = sign_keys_vec[i].phase2_delta_i(&alpha_vec[..], &beta_vec_all[i]);
        let sigma = sign_keys_vec[i].phase2_sigma_i(&miu_vec[..], &ni_vec_all[i]);
        delta_vec.push(delta);
        sigma_vec.push(sigma);
    }
    
    // writeln!(file, "phase2-mta protocol: delta_i={:?}, sigma_i={:?}", delta_vec[1], sigma_vec[1]).unwrap();
    
    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // writeln!(file, "phase3-reconstruct_delta: delta_inv={:?}", delta_inv).unwrap();
    
    // de-commit to g^gamma_i from phase1, test comm correctness, and that it is the same value used in MtA.
    // Return R

    let _g_gamma_i_vec = (0..ttag)
        .map(|i| sign_keys_vec[i].g_gamma_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();

    let R_vec = (0..ttag)
        .map(|_| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let b_proof_vec = (0..ttag)
                .map(|j| {
                    let b_gamma_vec = &m_b_gamma_vec_all[j];
                    &b_gamma_vec[0].b_proof
                })
                .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
            SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec)
                .expect("bad gamma_i decommit")
        })
        .collect::<Vec<Point<Secp256k1>>>();

    // writeln!(file, "phase4-gamma_i decommit: R={:?}", R_vec[1]).unwrap();

    let message: [u8; 4] = [79, 77, 69, 82];
    let message_bn = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(&message[..]))
        .result_bigint();
    let mut local_sig_vec = Vec::new();

    // each party computes s_i but don't send it yet. we start with phase5
    for i in 0..ttag {
        let local_sig = LocalSignature::phase5_local_sig(
            &sign_keys_vec[i].k_i,
            &message_bn,
            &R_vec[i],
            &sigma_vec[i],
            &y,
        );
        local_sig_vec.push(local_sig);
    }

    let mut phase5_com_vec: Vec<Phase5Com1> = Vec::new();
    let mut phase_5a_decom_vec: Vec<Phase5ADecom1> = Vec::new();
    let mut helgamal_proof_vec = Vec::new();
    let mut dlog_proof_rho_vec = Vec::new();
    // we notice that the proof for V= R^sg^l, B = A^l is a general form of homomorphic elgamal.
    for sig in &local_sig_vec {
        let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
            sig.phase5a_broadcast_5b_zkproof();
        phase5_com_vec.push(phase5_com);
        phase_5a_decom_vec.push(phase_5a_decom);
        helgamal_proof_vec.push(helgamal_proof);
        dlog_proof_rho_vec.push(dlog_proof_rho);
    }

    let mut phase5_com2_vec = Vec::new();
    let mut phase_5d_decom2_vec = Vec::new();
    for i in 0..ttag {
        let mut phase_5a_decom_vec_clone = phase_5a_decom_vec.clone();
        let mut phase_5a_com_vec_clone = phase5_com_vec.clone();
        let mut phase_5b_elgamal_vec_clone = helgamal_proof_vec.clone();

        let _decom_i = phase_5a_decom_vec_clone.remove(i);
        let _com_i = phase_5a_com_vec_clone.remove(i);
        let _elgamal_i = phase_5b_elgamal_vec_clone.remove(i);
        //        for j in 0..s_minus_i.len() {
        let (phase5_com2, phase_5d_decom2) = local_sig_vec[i]
            .phase5c(
                &phase_5a_decom_vec_clone,
                &phase_5a_com_vec_clone,
                &phase_5b_elgamal_vec_clone,
                &dlog_proof_rho_vec,
                &phase_5a_decom_vec[i].V_i,
                &R_vec[0],
            )
            .expect("error phase5");
        phase5_com2_vec.push(phase5_com2);
        phase_5d_decom2_vec.push(phase_5d_decom2);
        //        }
    }

    // assuming phase5 checks passes each party sends s_i and compute sum_i{s_i}
    let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    for sig in &local_sig_vec {
        let s_i = sig
            .phase5d(&phase_5d_decom2_vec, &phase5_com2_vec, &phase_5a_decom_vec)
            .expect("bad com 5d");
        s_vec.push(s_i);
    }

    // writeln!(file, "phase5-compute s_i: s_i={:?}", s_vec[1]).unwrap();
    
    // here we compute the signature only of party i=0 to demonstrate correctness.
    s_vec.remove(0);
    let sig = local_sig_vec[0]
        .output_signature(&s_vec)
        .expect("verification failed");

    assert_eq!(local_sig_vec[0].y, y);
    verify(&sig, &local_sig_vec[0].y, &local_sig_vec[0].m).unwrap();
    check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &y);

    // writeln!(file, "sig: sig={:?}", sig).unwrap();
}

fn check_sig(r: &Scalar<Secp256k1>, s: &Scalar<Secp256k1>, msg: &BigInt, pk: &Point<Secp256k1>) {
    use secp256k1::{Message, PublicKey, Signature, SECP256K1};

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::from_slice(msg.as_slice()).unwrap();
    let slice = pk.to_bytes(false);
    let mut raw_pk = Vec::new();
    if slice.len() != 65 {
        // after curv's pk_to_key_slice return 65 bytes, this can be removed
        raw_pk.insert(0, 4u8);
        raw_pk.extend(vec![0u8; 64 - slice.len()]);
        raw_pk.extend(slice.as_ref());
    } else {
        raw_pk.extend(slice.as_ref());
    }

    assert_eq!(raw_pk.len(), 65);

    let pk = PublicKey::from_slice(&raw_pk).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::from_compact(compact.as_slice()).unwrap();

    println!("secp_sig: {:?}", secp_sig);//打印

    let is_correct = SECP256K1.verify(&msg, &secp_sig, &pk).is_ok();
    assert!(is_correct);
}

async fn send_and_receive_tcp(ip: &str, port: &str, message: &str) -> Result<(), anyhow::Error> {
    // 格式化地址
    let address = format!("{}:{}", ip, port);

    // 连接到 TCP 服务器
    let mut stream = TcpStream::connect(&address)
        .with_context(|| format!("Failed to connect to {}", address))?;

    // 发送消息
    stream
        .write_all(message.as_bytes())
        .with_context(|| format!("Failed to send message to {}", address))?;

    println!("Sent message '{}' to {}", message, address);
    Ok(())
}

pub async fn fetch_json_via_tcp(
    ip: &str,
    port: &str,
    file_path: &str,
) -> Result<Value, Box<dyn Error>> {
    // 重试参数（固定值）
    const MAX_RETRIES: usize = 5; // 最大重试次数
    const INITIAL_DELAY: Duration = Duration::from_secs(1); // 初始等待时间

    let mut retries = 0;
    let mut delay = INITIAL_DELAY;

    loop {
        // 尝试连接服务器
        let address = format!("{}:{}", ip, port);
        match tokio::net::TcpStream::connect(&address).await {
            Ok(mut stream) => {
                println!("Connected to server at {}:{}", ip, port);

                // 发送请求（文件路径）
                let request = format!("GET {}\n", file_path); // 自定义协议：发送文件路径
                if let Err(e) = stream.write_all(request.as_bytes()).await {
                    eprintln!("Failed to send request: {}. Retrying in {:?}...", e, delay);
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(format!("Max retries reached. Last error: {}", e).into());
                    }
                    sleep(delay).await;
                    delay = delay * 2; // 指数退避
                    continue;
                }
                println!("Sent request: {}", request.trim());

                // 接收响应
                let mut buffer = Vec::new();
                if let Err(e) = stream.read_to_end(&mut buffer).await {
                    eprintln!("Failed to read response: {}. Retrying in {:?}...", e, delay);
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(format!("Max retries reached. Last error: {}", e).into());
                    }
                    sleep(delay).await;
                    delay = delay * 2; // 指数退避
                    continue;
                }

                // 解析 JSON 数据
                let json_text = String::from_utf8(buffer)?;
                println!("Received JSON data: {}", json_text);
                let json_data = serde_json::from_str(&json_text)?;
                return Ok(json_data);
            }
            Err(e) => {
                eprintln!("Failed to connect to server: {}. Retrying in {:?}...", e, delay);
                retries += 1;
                if retries >= MAX_RETRIES {
                    return Err(format!("Max retries reached. Last error: {}", e).into());
                }
                sleep(delay).await;
                delay = delay * 2; // 指数退避
            }
        }
    }
}

pub async fn TCP_TS(ip: String, port: String, amount_value: i32) -> Result<(), anyhow::Error> {
    let mes = format!("tx,127.0.0.1,8083");
    send_and_receive_tcp(&ip, &port, &mes).await?;

    // 从 key_data 中读取 keys
    let key_data = load_key_data()?;
    let s = vec![0usize, 1usize];
    let mut party_keys_vec = key_data.party_keys_vec;
    let mut shared_keys_vec = key_data.shared_keys_vec;
    let mut _pk_vec = key_data.pk_vec;
    let mut y = key_data.y;
    let mut vss_scheme = key_data.vss_scheme;
    let mut private_vec = key_data.private_vec;
    let mut sign_keys_vec = key_data.sign_keys_vec;

    // Phase1
    let (mut bc1_vec, mut decommit_vec1): (Vec<_>, Vec<_>) =
        sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();
    let mut m_a_vec: Vec<_> = sign_keys_vec
        .iter()
        .enumerate()
        .map(|(i, k)| MessageA::a(&k.k_i, &party_keys_vec[usize::from(s[i])].ek, &[]).0)
        .collect();

    // 写入 tcp1.json，并请求对方的 tcp1.json 数据 (Phase1 中间数据)
    let file = File::create("tcp1.json").await.context("Failed to create tcp1.json")?;
    let data = serde_json::json!({
        "bc1": bc1_vec[0],
        "decommit1": decommit_vec1[0],
        "m_a": m_a_vec[0],
    });
    to_writer(file.into_std().await, &data).context("Failed to write tcp1.json")?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp(&ip, &port, "/tcp1.json").await {
            Ok(data) => break data,
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    };

    let bc1 = json_data.get("bc1").context("bc1_vec not found")?;
    let decommit1 = json_data.get("decommit1").context("decommit_vec1 not found")?;
    let m_a = json_data.get("m_a").context("m_a_vec not found")?;

    bc1_vec[1] = from_value(bc1.clone()).context("Failed to deserialize bc1")?;
    decommit_vec1[1] = from_value(decommit1.clone()).context("Failed to deserialize decommit1")?;
    m_a_vec[1] = from_value(m_a.clone()).context("Failed to deserialize m_a")?;

    // Phase1 结果聚合
    let mut m_b_gamma_vec_all = Vec::new();
    let mut beta_vec_all = Vec::new();
    let mut m_b_w_vec_all = Vec::new();
    let mut ni_vec_all = Vec::new();

    for (i, key) in sign_keys_vec.iter().enumerate() {
        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for j in 0..1 {
            let ind = if j < i { j } else { j + 1 };

            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &key.gamma_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .map_err(|e| anyhow::anyhow!("Failed to create MessageB: {:?}", e))?;
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &key.w_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .map_err(|e| anyhow::anyhow!("Failed to create MessageB: {:?}", e))?;

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
        beta_vec_all.push(beta_vec.clone());
        m_b_w_vec_all.push(m_b_w_vec.clone());
        ni_vec_all.push(ni_vec.clone());
    }

    // Phase2
    let m_b_gamma_vec_i = &m_b_gamma_vec_all[1];
    let m_b_w_vec_i = &m_b_w_vec_all[1];
    let m_b = m_b_gamma_vec_i[0].clone();

    let mut alpha_ij_gamma = m_b
        .verify_proofs_get_alpha(
            &party_keys_vec[usize::from(s[0])].dk,
            &sign_keys_vec[0].k_i,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create MessageB: {:?}", e))?;
    let m_b = m_b_w_vec_i[0].clone();
    let mut alpha_ij_wi = m_b
        .verify_proofs_get_alpha(
            &party_keys_vec[usize::from(s[0])].dk,
            &sign_keys_vec[0].k_i,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create MessageB: {:?}", e))?;

    // Phase2 中间数据
    let file = File::create("tcp2.json").await.context("Failed to create tcp2.json")?;
    let data = serde_json::json!({
        "m_b_gamma_vec_all": m_b_gamma_vec_all[0],
        "m_b_w_vec_all": m_b_w_vec_all[0],
        "alpha_ij_gamma": alpha_ij_gamma,
        "alpha_ij_wi": alpha_ij_wi
    });
    to_writer(file.into_std().await, &data).context("Failed to write tcp2.json")?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp(&ip, &port, "/tcp2.json").await {
            Ok(data) => break data,
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    };
    
    // 提取数据
    m_b_gamma_vec_all[1] = from_value(json_data.get("m_b_gamma_vec_all").context("m_b_gamma_vec_all not found")?.clone())?;
    m_b_w_vec_all[1] = from_value(json_data.get("m_b_w_vec_all").context("m_b_w_vec_all not found")?.clone())?;
    alpha_ij_gamma = from_value(json_data.get("alpha_ij_gamma").context("alpha_ij_gamma not found")?.clone())?;
    alpha_ij_wi = from_value(json_data.get("alpha_ij_wi").context("alpha_ij_wi not found")?.clone())?;

    let mut alpha_vec_all = Vec::new();
    let mut miu_vec_all = Vec::new();

    for i in 0..2 {
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let m_b_gamma_vec_i = &m_b_gamma_vec_all[i];
        let m_b_w_vec_i = &m_b_w_vec_all[i];

        for j in 0..1 {
            let ind = if j < i { j } else { j + 1 };
            let m_b = m_b_w_vec_i[j].clone();
            if ind==0{
                let m_b = m_b_gamma_vec_i[j].clone();
                alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(
                        &party_keys_vec[usize::from(s[ind])].dk,
                        &sign_keys_vec[ind].k_i,
                    )
                    .expect("wrong dlog or m_b");
                alpha_ij_wi = m_b
                .verify_proofs_get_alpha(
                    &party_keys_vec[usize::from(s[ind])].dk,
                    &sign_keys_vec[ind].k_i,
                )
                .expect("wrong dlog or m_b");
            }
            assert_eq!(m_b.b_proof.pk, sign_keys_vec[i].g_w_i);

            alpha_vec.push(alpha_ij_gamma.clone());
            miu_vec.push(alpha_ij_wi.clone());
        }
        alpha_vec_all.push(alpha_vec.clone());
        miu_vec_all.push(miu_vec.clone());
    }


    let mut delta_vec = Vec::new();
    let mut sigma_vec = Vec::new();

    let alpha_vec: Vec<Scalar<Secp256k1>> = (0..alpha_vec_all[0].len())
        .map(|j| alpha_vec_all[0][j].0.clone())
        .collect();
    let miu_vec: Vec<Scalar<Secp256k1>> = (0..miu_vec_all[0].len())
        .map(|j| miu_vec_all[0][j].0.clone())
        .collect();
    let delta = sign_keys_vec[0].phase2_delta_i(&alpha_vec[..], &beta_vec_all[0]);
    let sigma = sign_keys_vec[0].phase2_sigma_i(&miu_vec[..], &ni_vec_all[0]);
    delta_vec.push(delta.clone());
    sigma_vec.push(sigma.clone());


    //写入数据
    let file = File::create("tcp3.json").await.context("Failed to create tcp2.json")?; // 覆盖文件
    let data = serde_json::json!({
        "delta": delta,
        "sigma": sigma,
    });
    to_writer(file.into_std().await, &data).context("Failed to write tcp2.json")?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp(&ip, &port, "/tcp3.json").await {
            Ok(data) => break data,
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    };
    
    // 提取数据
    let delta1 = from_value(json_data.get("delta").context("_g_gamma_i_vec not found")?.clone())?;
    let sigma1 = from_value(json_data.get("sigma").context("_g_gamma_i_vec not found")?.clone())?;
    delta_vec.push(delta1);
    sigma_vec.push(sigma1);

    // Phase3
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // Phase4
    let mut _g_gamma_i_vec = (0..2)
        .map(|i| sign_keys_vec[i].g_gamma_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();

    // 写入数据
    let file = File::create("tcp4.json").await.context("Failed to create tcp4.json")?;
    let data = serde_json::json!({
        "_g_gamma_i_vec": _g_gamma_i_vec[0]
    });
    to_writer(file.into_std().await, &data).context("Failed to write tcp4.json")?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp(&ip, &port, "/tcp4.json").await {
            Ok(data) => break data,
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    };

    // 提取数据
    _g_gamma_i_vec[1] = from_value(json_data.get("_g_gamma_i_vec").context("_g_gamma_i_vec not found")?.clone())?;

    let R_vec = (0..2)
        .map(|_| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let b_proof_vec = (0..2)
                .map(|j| {
                    let b_gamma_vec = &m_b_gamma_vec_all[j];
                    &b_gamma_vec[0].b_proof
                })
                .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
            SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec)
                .expect("bad gamma_i decommit")
        })
        .collect::<Vec<Point<Secp256k1>>>();

    // 准备消息
    let message: [u8; 1] = [1];
    let message_bn = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(&message[..]))
        .result_bigint();
    let mut local_sig_vec = Vec::new();


    // Phase5
    let local_sig = LocalSignature::phase5_local_sig(
        &sign_keys_vec[0].k_i,
        &message_bn,
        &R_vec[0],
        &sigma_vec[0],
        &y,
    );
    local_sig_vec.push(local_sig.clone());

    // 写入数据
    let file = File::create("tcp5.json").await.context("Failed to create tcp5.json")?;
    let data = serde_json::json!({
        "local_sig": local_sig
    });
    to_writer(file.into_std().await, &data).context("Failed to write tcp5.json")?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp(&ip, &port, "/tcp5.json").await {
            Ok(data) => break data,
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    };

    // 提取数据
    let local_sig1 = from_value(json_data.get("local_sig").context("local_sig not found")?.clone())?;
    local_sig_vec.push(local_sig1);


    // 向银行发送签名
    let mes = format!("success;{};{}",amount_value,serde_json::json!({
        "sigma": local_sig_vec,
    }));
    send_and_receive_tcp("127.0.0.1", "8081", &mes).await?;

    
    // let mut phase5_com_vec: Vec<Phase5Com1> = Vec::new();
    // let mut phase_5a_decom_vec: Vec<Phase5ADecom1> = Vec::new();
    // let mut helgamal_proof_vec = Vec::new();
    // let mut dlog_proof_rho_vec = Vec::new();


    // for sig in &local_sig_vec {
    //     let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
    //         sig.phase5a_broadcast_5b_zkproof();
    //     phase5_com_vec.push(phase5_com);
    //     phase_5a_decom_vec.push(phase_5a_decom);
    //     helgamal_proof_vec.push(helgamal_proof);
    //     dlog_proof_rho_vec.push(dlog_proof_rho);
    // }

    // let mut phase5_com2_vec = Vec::new();
    // let mut phase_5d_decom2_vec = Vec::new();
    // for i in 0..2 {
    //     let mut phase_5a_decom_vec_clone = phase_5a_decom_vec.clone();
    //     let mut phase_5a_com_vec_clone = phase5_com_vec.clone();
    //     let mut phase_5b_elgamal_vec_clone = helgamal_proof_vec.clone();

    //     let _decom_i = phase_5a_decom_vec_clone.remove(i);
    //     let _com_i = phase_5a_com_vec_clone.remove(i);
    //     let _elgamal_i = phase_5b_elgamal_vec_clone.remove(i);

    //     let (phase5_com2, phase_5d_decom2) = local_sig_vec[i]
    //         .phase5c(
    //             &phase_5a_decom_vec_clone,
    //             &phase_5a_com_vec_clone,
    //             &phase_5b_elgamal_vec_clone,
    //             &dlog_proof_rho_vec,
    //             &phase_5a_decom_vec[i].V_i,
    //             &R_vec[0],
    //         )
    //         .expect("error phase5");
    //     phase5_com2_vec.push(phase5_com2);
    //     phase_5d_decom2_vec.push(phase_5d_decom2);
    // }

    // let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // for sig in &local_sig_vec {
    //     let s_i = sig
    //         .phase5d(&phase_5d_decom2_vec, &phase5_com2_vec, &phase_5a_decom_vec)
    //         .expect("bad com 5d");
    //     s_vec.push(s_i);
    // }


    // let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    // s_vec.remove(0);
    // let sig = local_sig_vec[0]
    //     .output_signature(&s_vec)
    //     .expect("verification failed");


    Ok(())
}


pub async fn fetch_json_via_tcp1(ip: &str, port: &str, file_path: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // 连接到服务器
    let address = format!("{}:{}", ip, port);
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    println!("Connected to server at {}:{}", ip, port);

    // 发送请求（文件路径）
    let request = format!("GET {}\n", file_path); // 自定义协议：发送文件路径
    stream.write_all(request.as_bytes()).await.unwrap();
    println!("Sent request: {}", request.trim());

    // 接收响应
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();;
    let json_text = String::from_utf8(buffer)?;
    println!("Received JSON data: {}", json_text);

    // 解析 JSON 数据
    let json_data = serde_json::from_str(&json_text)?;
    Ok(json_data)
}

pub async fn TCP_Reply(ip: &str, port: &str)-> Result<(), Box<dyn std::error::Error>>{

    //从key_data中读取keys
    let key_data = load_key_data()?;
    let s= vec![0usize, 1usize];
    let mut party_keys_vec = key_data.party_keys_vec;
    let mut shared_keys_vec = key_data.shared_keys_vec;
    let mut _pk_vec = key_data.pk_vec;
    let mut y = key_data.y;
    let mut vss_scheme = key_data.vss_scheme;
    let mut private_vec = key_data.private_vec;
    let mut sign_keys_vec = key_data.sign_keys_vec;

    // Phase1
    let (mut bc1_vec,mut decommit_vec1): (Vec<_>, Vec<_>) =
    sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();
    let mut m_a_vec: Vec<_> = sign_keys_vec
    .iter()
    .enumerate()
    .map(|(i, k)| MessageA::a(&k.k_i, &party_keys_vec[usize::from(s[i])].ek, &[]).0)
    .collect();


    //写入tcp1.json，并请求对方的tcp1.json数据(Phase1中间数据)
    let file = std::fs::File::create("tcp1.json")?; // 覆盖文件
    let data = serde_json::json!({
        "bc1": bc1_vec[1],
        "decommit1": decommit_vec1[1],
        "m_a": m_a_vec[1],
    });
    to_writer(file, &data)?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp1(&ip, &port, "/tcp1.json").await {
            Ok(data) => break data, // 成功获取数据，退出循环
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                thread::sleep(Duration::from_secs(1)); // 等待 1 秒后重试
            }
        }
    };

    // 提取数据
    bc1_vec[0] = from_value(json_data.get("bc1").ok_or("bc1_vec not found")?.clone())?;
    decommit_vec1[0] = from_value(json_data.get("decommit1").ok_or("decommit_vec1 not found")?.clone())?;
    m_a_vec[0] = from_value(json_data.get("m_a").ok_or("m_a_vec not found")?.clone())?;


    //Phase1结果聚合
    let mut m_b_gamma_vec_all = Vec::new();
    let mut beta_vec_all = Vec::new();
    let mut m_b_w_vec_all = Vec::new();
    let mut ni_vec_all = Vec::new();

    for (i, key) in sign_keys_vec.iter().enumerate() {
        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for j in 0..1 {
            let ind = if j < i { j } else { j + 1 };

            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &key.gamma_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &key.w_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .unwrap();

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
        beta_vec_all.push(beta_vec.clone());
        m_b_w_vec_all.push(m_b_w_vec.clone());
        ni_vec_all.push(ni_vec.clone());
    }


    // Phase2 
    let m_b_gamma_vec_i = &m_b_gamma_vec_all[0];
    let m_b_w_vec_i = &m_b_w_vec_all[0];
    let m_b = m_b_gamma_vec_i[0].clone();
    let mut alpha_ij_gamma = m_b
        .verify_proofs_get_alpha(
            &party_keys_vec[usize::from(s[1])].dk,
            &sign_keys_vec[1].k_i,
        )
        .expect("wrong dlog or m_b");
    let m_b = m_b_w_vec_i[0].clone();
    let mut alpha_ij_wi = m_b
        .verify_proofs_get_alpha(
            &party_keys_vec[usize::from(s[1])].dk,
            &sign_keys_vec[1].k_i,
        )
        .expect("wrong dlog or m_b");


    //Phase2中间数据
    let file = std::fs::File::create("tcp2.json")?; // 覆盖文件
    let data = serde_json::json!({
        "m_b_gamma_vec_all": m_b_gamma_vec_all[1],
        "m_b_w_vec_all": m_b_w_vec_all[1],
        "alpha_ij_gamma": alpha_ij_gamma,
        "alpha_ij_wi": alpha_ij_wi
    });
    to_writer(file, &data)?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp1(&ip, &port, "/tcp2.json").await {
            Ok(data) => break data, // 成功获取数据，退出循环
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                thread::sleep(Duration::from_secs(1)); // 等待 1 秒后重试
            }
        }
    };

    let mut alpha_ij_gamma0 = alpha_ij_gamma.clone();
    let mut alpha_ij_wi0 = alpha_ij_wi.clone();
    // 提取数据
    m_b_gamma_vec_all[0] = from_value(json_data.get("m_b_gamma_vec_all").ok_or("bc1_vec not found")?.clone())?;
    m_b_w_vec_all[0] = from_value(json_data.get("m_b_w_vec_all").ok_or("decommit_vec1 not found")?.clone())?;
    alpha_ij_gamma0 = from_value(json_data.get("alpha_ij_gamma").ok_or("m_a_vec not found")?.clone())?;
    alpha_ij_wi0 = from_value(json_data.get("alpha_ij_wi").ok_or("m_a_vec not found")?.clone())?;

    let mut alpha_vec_all = Vec::new();
    let mut miu_vec_all = Vec::new();

    for i in 0..2 {
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let m_b_w_vec_i = &m_b_w_vec_all[i];

        for j in 0..1 {
            let ind = if j < i { j } else { j + 1 };
            let m_b = m_b_w_vec_i[j].clone();
            if ind==1{
                alpha_vec.push(alpha_ij_gamma.clone());
                miu_vec.push(alpha_ij_wi.clone());
            }else{
                alpha_vec.push(alpha_ij_gamma0.clone());
                miu_vec.push(alpha_ij_wi0.clone());
            }
            assert_eq!(m_b.b_proof.pk, sign_keys_vec[i].g_w_i);
        }
        alpha_vec_all.push(alpha_vec.clone());
        miu_vec_all.push(miu_vec.clone());
    }

    let mut delta_vec = Vec::new();
    let mut sigma_vec = Vec::new();

    let alpha_vec: Vec<Scalar<Secp256k1>> = (0..alpha_vec_all[1].len())
        .map(|j| alpha_vec_all[1][j].0.clone())
        .collect();
    let miu_vec: Vec<Scalar<Secp256k1>> = (0..miu_vec_all[1].len())
        .map(|j| miu_vec_all[1][j].0.clone())
        .collect();
    let delta = sign_keys_vec[1].phase2_delta_i(&alpha_vec[..], &beta_vec_all[1]);
    let sigma = sign_keys_vec[1].phase2_sigma_i(&miu_vec[..], &ni_vec_all[1]);

    //写入数据
    let file = std::fs::File::create("tcp3.json")?; // 覆盖文件
    let data = serde_json::json!({
        "delta": delta,
        "sigma": sigma,
    });
    to_writer(file, &data)?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp1(&ip, &port, "/tcp3.json").await {
            Ok(data) => break data, // 成功获取数据，退出循环
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                thread::sleep(Duration::from_secs(1)); // 等待 1 秒后重试
            }
        }
    };

    // 提取数据
    let delta1 = from_value(json_data.get("delta").ok_or("bc1_vec not found")?.clone())?;
    let sigma1 = from_value(json_data.get("sigma").ok_or("decommit_vec1 not found")?.clone())?;
    delta_vec.push(delta1);
    sigma_vec.push(sigma1);


    delta_vec.push(delta);
    sigma_vec.push(sigma);

    // Phase3
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        
    // Phase4
    let mut _g_gamma_i_vec = (0..2)
        .map(|i| sign_keys_vec[i].g_gamma_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();

    //写入数据
    let file = std::fs::File::create("tcp4.json")?; // 覆盖文件
    let data = serde_json::json!({
        "_g_gamma_i_vec": _g_gamma_i_vec[1]
    });
    to_writer(file, &data)?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp1(&ip, &port, "/tcp4.json").await {
            Ok(data) => break data, // 成功获取数据，退出循环
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                thread::sleep(Duration::from_secs(1)); // 等待 1 秒后重试
            }
        }
    };

    // 提取数据
    _g_gamma_i_vec[0] = from_value(json_data.get("_g_gamma_i_vec").ok_or("bc1_vec not found")?.clone())?;


    let R_vec = (0..2)
        .map(|_| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let b_proof_vec = (0..2)
                .map(|j| {
                    let b_gamma_vec = &m_b_gamma_vec_all[j];
                    &b_gamma_vec[0].b_proof
                })
                .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
            SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec)
                .expect("bad gamma_i decommit")
        })
        .collect::<Vec<Point<Secp256k1>>>();

    // 准备消息
    let message: [u8; 1] = [1];
    let message_bn = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(&message[..]))
        .result_bigint();
    let mut local_sig_vec = Vec::new();

    // Phase5，此处做了多处简化，之后还需不断补充
    let local_sig = LocalSignature::phase5_local_sig(
        &sign_keys_vec[1].k_i,
        &message_bn,
        &R_vec[1],
        &sigma_vec[1],
        &y,
    );

    //写入数据
    let file = std::fs::File::create("tcp5.json")?; // 覆盖文件
    let data = serde_json::json!({
        "local_sig": local_sig
    });
    to_writer(file, &data)?;

    // 循环请求，直到成功获取数据
    let json_data = loop {
        match fetch_json_via_tcp1(&ip, &port, "/tcp5.json").await {
            Ok(data) => break data, // 成功获取数据，退出循环
            Err(e) => {
                eprintln!("Failed to fetch data: {}. Retrying in 1 second...", e);
                thread::sleep(Duration::from_secs(1)); // 等待 1 秒后重试
            }
        }
    };

    // 提取数据
    let local_sig1= from_value(json_data.get("local_sig").ok_or("bc1_vec not found")?.clone())?;
    local_sig_vec.push(local_sig1);

    local_sig_vec.push(local_sig);

    // let mut phase5_com_vec: Vec<Phase5Com1> = Vec::new();
    // let mut phase_5a_decom_vec: Vec<Phase5ADecom1> = Vec::new();
    // let mut helgamal_proof_vec = Vec::new();
    // let mut dlog_proof_rho_vec = Vec::new();

    // for sig in &local_sig_vec {
    //     let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
    //         sig.phase5a_broadcast_5b_zkproof();
    //     phase5_com_vec.push(phase5_com);
    //     phase_5a_decom_vec.push(phase_5a_decom);
    //     helgamal_proof_vec.push(helgamal_proof);
    //     dlog_proof_rho_vec.push(dlog_proof_rho);
    // }

    // let mut phase5_com2_vec = Vec::new();
    // let mut phase_5d_decom2_vec = Vec::new();
    // for i in 0..2 {
    //     let mut phase_5a_decom_vec_clone = phase_5a_decom_vec.clone();
    //     let mut phase_5a_com_vec_clone = phase5_com_vec.clone();
    //     let mut phase_5b_elgamal_vec_clone = helgamal_proof_vec.clone();

    //     let _decom_i = phase_5a_decom_vec_clone.remove(i);
    //     let _com_i = phase_5a_com_vec_clone.remove(i);
    //     let _elgamal_i = phase_5b_elgamal_vec_clone.remove(i);

    //     let (phase5_com2, phase_5d_decom2) = local_sig_vec[i]
    //         .phase5c(
    //             &phase_5a_decom_vec_clone,
    //             &phase_5a_com_vec_clone,
    //             &phase_5b_elgamal_vec_clone,
    //             &dlog_proof_rho_vec,
    //             &phase_5a_decom_vec[i].V_i,
    //             &R_vec[0],
    //         )
    //         .expect("error phase5");
    //     phase5_com2_vec.push(phase5_com2);
    //     phase_5d_decom2_vec.push(phase_5d_decom2);
    // }

    // let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    // for sig in &local_sig_vec {
    //     let s_i = sig
    //         .phase5d(&phase_5d_decom2_vec, &phase5_com2_vec, &phase_5a_decom_vec)
    //         .expect("bad com 5d");
    //     s_vec.push(s_i);
    // }


    // let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    // s_vec.remove(0);
    // let sig = local_sig_vec[0]
    //     .output_signature(&s_vec)
    //     .expect("verification failed");


    Ok(())
}


#[test]
fn test_serialize_deserialize() {
    use serde_json;

    let k = Keys::create(0);
    let (commit, decommit) = k.phase1_broadcast_phase3_proof_of_correct_key();

    let encoded = serde_json::to_string(&commit).unwrap();
    let decoded: KeyGenBroadcastMessage1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(commit.com, decoded.com);

    let encoded = serde_json::to_string(&decommit).unwrap();
    let decoded: KeyGenDecommitMessage1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decommit.y_i, decoded.y_i);
}

