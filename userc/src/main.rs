mod gg_2018;
pub mod mta;

use eframe::{self, egui};
use std::io::{Read, Write};
use tokio::net::{TcpStream, TcpListener};
use tokio::sync::{Mutex};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use crate::gg_2018::test;
use std::fs;
use tokio::runtime::Runtime; 
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::egui::Context;
use egui::{Ui};
use eframe::Frame;
use tokio::task::LocalSet;

async fn send_tcp(ip: &str, port: &str, message: &str) -> Result<(), String> {
    let address = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect(&address).await.map_err(|e| e.to_string())?;
    println!("Connected to {}", address);
    stream.write_all(message.as_bytes()).await.map_err(|e| e.to_string())?;
    println!("Sent message '{}' to {}", message, address);
    Ok(())
}

async fn send_and_receive_tcp(ip: &str, port: &str, message: &str) -> Result<String, String> {
    let address = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect(&address).await.map_err(|e| e.to_string())?;
    println!("Connected to {}", address);
    stream.write_all(message.as_bytes()).await.map_err(|e| e.to_string())?;
    println!("Sent message '{}' to {}", message, address);
    let mut buffer = [0; 1024];
    let size = stream.read(&mut buffer).await.map_err(|e| e.to_string())?;
    let response = String::from_utf8_lossy(&buffer[..size]).to_string();
    println!("Received response: {}", response);
    Ok(response)
}

async fn handle_client(mut stream: TcpStream, received_message: Arc<Mutex<String>>, balance: Arc<Mutex<f32>>) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer).await {
        Ok(size) => {
            let received = String::from_utf8_lossy(&buffer[..size]);
            println!("Received message: {}", received);
            
            {            
            let mut received_message = received_message.lock().await;
            *received_message = received.to_string();
            }

            if received.starts_with("GET ") {
                let file_path = received.trim_start_matches("GET ").trim();
                println!("Requested file: {}", file_path);
                let full_path = format!("./{}", file_path.trim_start_matches('/'));
                let file_content = tokio::fs::read_to_string(&full_path).await.unwrap_or_else(|_| {
                    "File not found".to_string()
                });
                stream.write_all(file_content.as_bytes()).await.unwrap();
                println!("Sent file content to client");
                {
                    let mut received_message = received_message.lock().await;
                    *received_message = String::new();
                }
            } else if received.starts_with("tx,") {
                let parts: Vec<&str> = received.split(',').collect();
                // if parts.len() == 2 {
                //     if let Ok(amount) = parts[1].parse::<f32>() {
                //         let mut balance = balance.lock().await;
                //         *balance -= amount;
                //         println!("Updated balance: {}", *balance);
                //     }
                // }
                // {
                //     let mut received_message = received_message.lock().await;
                //     *received_message = String::new();
                // }
                println!("Cleared received message due to 'tx,' prefix.");
                gg_2018::test::TCP_Reply(parts[1], parts[2]).await;
            } else if received.starts_with("success,"){
                let parts: Vec<&str> = received.split(',').collect();
                if parts.len() == 2 {
                    if let Ok(amount) = parts[1].parse::<f32>() {
                        let mut balance = balance.lock().await;
                        *balance -= amount;
                        println!("Updated balance: {}", *balance);
                    }
                }
            }else{
                stream.write_all(b"Received your message").await.unwrap();
            }
        }
        Err(e) => {
            eprintln!("Failed to read from stream: {}", e);
        }
    }
}

async fn start_listener(ip: String, port: String, received_message: Arc<Mutex<String>>, balance: Arc<Mutex<f32>>) {
    println!("IP: {}, Port: {}", ip, port);
    let listener = TcpListener::bind(format!("{}:{}", ip, port)).await.unwrap();
    println!("Listening on {}:{}", ip, port);
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let received_message = received_message.clone();
        let balance = balance.clone();

        // 使用 std::thread::spawn 创建新线程
        thread::spawn(move || {
            // 在当前线程中运行 Tokio 运行时
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                handle_client(stream, received_message, balance).await;
            });
        });
    }
}

struct MyApp {
    counter: Arc<Mutex<i32>>,
    amount: String,
    bank_ip: String,
    bank_port: String,
    your_ip: String,
    your_port: String,
    tx_ip: String,
    tx_port: String,
    new_ip: String,
    new_port: String,
    saved_bank_ip: Option<String>,
    saved_bank_port: Option<String>,
    saved_your_ip: Option<String>,
    saved_your_port: Option<String>,
    saved_tx_ip: Option<String>,
    saved_tx_port: Option<String>,
    saved_new_ip: Option<String>,
    saved_new_port: Option<String>,
    balance: Arc<Mutex<f32>>,
    is_running: bool,
    status: Vec<String>,
    own_ip: String,
    own_port: String,
    received_message: Arc<Mutex<String>>,
    runtime: Arc<Runtime>,
}

impl MyApp {
    async fn send_prestart(&mut self) {
        if self.saved_bank_ip.is_none() || self.saved_bank_port.is_none() {
            self.add_status("Bank IP or Port not set".to_string());
            return;
        }

        let ip = self.saved_bank_ip.as_ref().unwrap();
        let port = self.saved_bank_port.as_ref().unwrap();

        match send_and_receive_tcp(ip, port, "prestart").await {
            Ok(response) => {
                self.add_status(format!("Prestart response: {}", response));
            }
            Err(err) => {
                eprintln!("Failed to send prestart: {}", err);
                self.add_status(format!("Failed to send prestart: {}", err));
            }
        }
    }

    async fn handle_start(
        saved_tx_ip: Option<String>,
        saved_tx_port: Option<String>,
        saved_new_ip: Option<String>,
        saved_new_port: Option<String>,
        balance: Arc<Mutex<f32>>,
        received_message: Arc<Mutex<String>>,
        amount_value: i32,
    ) {
        if saved_tx_ip.is_none() || saved_tx_port.is_none() {
            return;
        }
        {        
            let mut received_message = received_message.lock().await;
            *received_message = String::new();
        }

        let ip = saved_tx_ip.unwrap();
        let port = saved_tx_port.unwrap();
        let message = format!("tx,{}", amount_value);
    
        // 使用 spawn_blocking 将同步任务转换为异步任务
        let ip_clone = ip.clone();
        let port_clone = port.clone();
    
        // 创建 LocalSet
        let local_set = LocalSet::new();

        // 在 LocalSet 中运行任务
        local_set.run_until(async move {
            let handle = tokio::task::spawn_local(async move {
                if let Err(e) = gg_2018::test::TCP_TS(ip, port, amount_value).await {
                    eprintln!("Error in TCP_TS: {}", e);
                }
            });

            // 等待任务完成
            handle.await;
        }).await;

        // 继续执行其他逻辑
        // if let (Some(new_ip), Some(new_port)) = (saved_new_ip, saved_new_port) {
        //     match send_and_receive_tcp(&new_ip, &new_port, &message).await {
        //         Ok(response) => {
        //             let mut received_message = received_message.lock().await;
        //             *received_message = format!("New IP response: {}", response);
        //         }
        //         Err(err) => {
        //             eprintln!("Failed to send to new IP: {}", err);
        //             let mut received_message = received_message.lock().await;
        //             *received_message = format!("Failed to send to new IP: {}", err);
        //         }
        //     }
        // }

        // {
        //     let mut balance = balance.lock().await;
        //     *balance -= amount_value as f32;
        //     println!("Updated balance: {}", *balance);
        // }

        // {
        //     let mut received_message = received_message.lock().await;
        //     *received_message = String::new();
        // }
    }

    async fn send_status_to_bank(&mut self, status: &str) {
        if self.saved_bank_ip.is_none() || self.saved_bank_port.is_none() {
            self.add_status("Bank IP or Port not set".to_string());
            return;
        }

        let ip = self.saved_bank_ip.as_ref().unwrap();
        let port = self.saved_bank_port.as_ref().unwrap();

        let message = format!("{},{}", status, self.amount);
        if let Err(err) = send_tcp(ip, port, &message).await {
            eprintln!("Failed to send status to bank: {}", err);
            self.add_status(format!("Failed to send status to bank: {}", err));
        }
    }

    fn add_status(&mut self, new_status: String) {
        self.status.push(new_status);
    }

    fn start_listener_thread(&mut self) {
        let received_message = Arc::clone(&self.received_message);
        let balance = Arc::clone(&self.balance);
        let ip = self.own_ip.clone();
        let port = self.own_port.clone();

        self.runtime.spawn(async move {
            start_listener(ip, port, received_message, balance).await;
        });

        self.add_status(format!("Listening on {}:{}", self.own_ip, self.own_port));
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.label("Threshold Wallet: User A");
            ui.add_space(20.0);

            let balance = self.runtime.block_on(async {
                let balance = self.balance.lock().await;
                *balance
            });
            ui.label(format!("Balance: ￥{:.2}", balance));
            ui.add_space(20.0);

            ui.horizontal(|ui| {
                ui.label("Bank IP:");
                ui.add_sized(egui::vec2(120.0, 18.0), egui::TextEdit::singleline(&mut self.bank_ip));
                ui.label("Bank Port:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.bank_port));
                
                if ui.add_sized(egui::vec2(80.0, 18.0), egui::Button::new("Confirm")).clicked() {
                    self.saved_bank_ip = Some(self.bank_ip.clone());
                    self.saved_bank_port = Some(self.bank_port.clone());
                    self.add_status(format!("Bank IP: {} and Port: {} saved.", self.saved_bank_ip.as_ref().unwrap(), self.saved_bank_port.as_ref().unwrap()));
                }
            });

            if ui.add_sized(egui::vec2(80.0, 18.0), egui::Button::new("Prestart")).clicked() {
                let saved_bank_ip = self.saved_bank_ip.clone();
                let saved_bank_port = self.saved_bank_port.clone();
                let runtime = self.runtime.clone();
            
                runtime.spawn(async move {
                    if saved_bank_ip.is_none() || saved_bank_port.is_none() {
                        return;
                    }
            
                    let ip = saved_bank_ip.unwrap();
                    let port = saved_bank_port.unwrap();
            
                    match send_and_receive_tcp(&ip, &port, "prestart").await {
                        Ok(response) => {
                            println!("Prestart response: {}", response);
                        }
                        Err(err) => {
                            eprintln!("Failed to send prestart: {}", err);
                        }
                    }
                });
            }

            ui.horizontal(|ui| {
                ui.label("Your IP:");
                ui.add_sized(egui::vec2(120.0, 18.0), egui::TextEdit::singleline(&mut self.your_ip));
                ui.label("Your Port:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.your_port));
                
                if ui.add_sized(egui::vec2(80.0, 18.0), egui::Button::new("Start Listen")).clicked() {
                    self.saved_your_ip = Some(self.your_ip.clone());
                    self.saved_your_port = Some(self.your_port.clone());
                    self.own_ip = self.your_ip.clone();
                    self.own_port = self.your_port.clone();
                    self.start_listener_thread();
                }
            });

            ui.horizontal(|ui| {
                ui.label("Received Message:");
                let received_message = self.runtime.block_on(async {
                    let received_message = self.received_message.lock().await;
                    received_message.clone()
                });
                ui.label(&received_message);
            });

            ui.horizontal(|ui| {
                ui.label("Tx IP:");
                ui.add_sized(egui::vec2(120.0, 18.0), egui::TextEdit::singleline(&mut self.tx_ip));
                ui.label("Tx Port:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.tx_port));
                ui.label("Amount:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.amount));
                
                let is_start_button_enabled = !self.runtime.block_on(async {
                    let received_message = self.received_message.lock().await;
                    received_message.is_empty()
                });
                if ui.add_enabled(is_start_button_enabled, egui::Button::new("Start")).clicked() {
                    let saved_tx_ip = Some(self.tx_ip.clone());
                    let saved_tx_port = Some(self.tx_port.clone());
                    let saved_new_ip = self.saved_new_ip.clone();
                    let saved_new_port = self.saved_new_port.clone();
                    let balance = Arc::clone(&self.balance);
                    let received_message = Arc::clone(&self.received_message);
                    let amount_value: i32 = self.amount.parse().unwrap_or(0);
                    let runtime = self.runtime.clone();
                    runtime.block_on(async {
                        MyApp::handle_start(saved_tx_ip, saved_tx_port, saved_new_ip, saved_new_port, balance, received_message, amount_value).await;
                    });
                }
            });

            ui.horizontal(|ui| {
                ui.label("New IP:");
                ui.add_sized(egui::vec2(120.0, 18.0), egui::TextEdit::singleline(&mut self.new_ip));
                ui.label("New Port:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.new_port));
                
                if ui.add_sized(egui::vec2(80.0, 18.0), egui::Button::new("Save New")).clicked() {
                    self.saved_new_ip = Some(self.new_ip.clone());
                    self.saved_new_port = Some(self.new_port.clone());
                    self.add_status(format!("New IP: {} and Port: {} saved.", self.saved_new_ip.as_ref().unwrap(), self.saved_new_port.as_ref().unwrap()));
                }
            });

            for status in &self.status {
                ui.label(status);
            }
        });
    }
}

fn main() {
    let app = MyApp {
        counter: Arc::new(Mutex::new(0)),
        amount: String::new(),
        bank_ip: String::new(),
        bank_port: String::new(),
        your_ip: String::new(),
        your_port: String::new(),
        tx_ip: String::new(),
        tx_port: String::new(),
        new_ip: String::new(),
        new_port: String::new(),
        saved_bank_ip: None,
        saved_bank_port: None,
        saved_your_ip: None,
        saved_your_port: None,
        saved_tx_ip: None,
        saved_tx_port: None,
        saved_new_ip: None,
        saved_new_port: None,
        balance: Arc::new(Mutex::new(1000.0)),
        is_running: false,
        status: Vec::new(),
        own_ip: String::new(),
        own_port: String::new(),
        received_message: Arc::new(Mutex::new(String::new())),
        runtime: Arc::new(Runtime::new().unwrap()),
    };

    eframe::run_native("Threshold Wallet", eframe::NativeOptions::default(), Box::new(|_cc| Ok(Box::<MyApp>::new(app))));
}