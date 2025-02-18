// hardware.rs

use rusb::{Context, Device, DeviceDescriptor, UsbContext, Direction, TransferType};
use std::time::Duration;

// USB 设备的 Vendor ID 和 Product ID
const VENDOR_ID: u16 = 0x1234; // 假设 Vendor ID 是 0x1234
const PRODUCT_ID: u16 = 0x5678; // 假设 Product ID 是 0x5678

// 硬件命令常量
const COMMAND_DECRYPT: u8 = 1;  // 解密命令
const COMMAND_GG18_MUL: u8 = 2; // GG18乘法命令

// USB 设备的接口编号
const INTERFACE_ID: u8 = 0;

// 与硬件通信的函数
pub fn communicate_with_hardware(command: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    // 创建 USB 上下文
    let context = Context::new().map_err(|e| format!("Failed to initialize USB context: {}", e))?;

    // 查找目标设备
    let device = context
        .devices()
        .iter()
        .find(|device| {
            let desc = device.device_descriptor().unwrap();
            desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID
        })
        .ok_or("USB device not found")?;

    // 打开设备
    let mut handle = device.open().map_err(|e| format!("Failed to open device: {}", e))?;

    // 控制传输（通过USB发送命令）
    let mut buffer = vec![command];
    buffer.extend_from_slice(data);

    // 发送命令到硬件设备
    handle
        .write_bulk(0x01, &buffer, Duration::from_secs(1)) // 0x01 为端点地址
        .map_err(|e| format!("Failed to send data to hardware: {}", e))?;

    // 读取硬件响应
    let mut response = vec![0; 64]; // 假设最大响应大小为64字节
    let response_len = handle
        .read_bulk(0x81, &mut response, Duration::from_secs(1)) // 0x81 为输入端点
        .map_err(|e| format!("Failed to read response from hardware: {}", e))?;

    // 截取有效的响应数据
    response.truncate(response_len);
    Ok(response)
}

// 解密 Paillier 密文
pub fn decrypt_paillier_ciphertext(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    communicate_with_hardware(COMMAND_DECRYPT, ciphertext)
}

// 使用 GG18 私钥片段进行乘法操作
pub fn gg18_mul_sk(sk: &[u8], number: &[u8]) -> Result<Vec<u8>, String> {
    communicate_with_hardware(COMMAND_GG18_MUL, &[sk, number].concat()) // 连接私钥片段和数字
}
