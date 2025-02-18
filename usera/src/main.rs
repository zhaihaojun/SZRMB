mod gg_2018;
pub mod mta;

use eframe::{self, egui};
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn send_tcp(ip: &str, port: &str, message: &str) -> Result<(), String> {
    let address = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect(&address).map_err(|e| e.to_string())?;
    stream.write_all(message.as_bytes()).map_err(|e| e.to_string())?; 
    println!("Sent message '{}' to {}", message, address);
    Ok(())
}

fn send_and_receive_tcp(ip: &str, port: &str, message: &str) -> Result<String, String> {
    let address = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect(&address).map_err(|e| e.to_string())?;
    stream.write_all(message.as_bytes()).map_err(|e| e.to_string())?; 
    println!("Sent message '{}' to {}", message, address);

    let mut buffer = [0; 1024];
    let size = stream.read(&mut buffer).map_err(|e| e.to_string())?;
    let response = String::from_utf8_lossy(&buffer[..size]).to_string();
    println!("Received response: {}", response);

    Ok(response)
}

fn start_listener(ip: String, port: String, received_message: Arc<Mutex<String>>, balance: Arc<Mutex<f32>>) {
    println!("IP: {}, Port: {}", ip, port);

    thread::spawn(move || {
        let listener = TcpListener::bind(format!("{}:{}", ip, port));
        match listener {
            Ok(listener) => {
                println!("Listening on {}:{}", ip, port);
                for stream in listener.incoming() {
                    match stream {
                        Ok(mut stream) => {
                            let mut buffer = [0; 1024];
                            match stream.read(&mut buffer) {
                                Ok(size) => {
                                    let received = String::from_utf8_lossy(&buffer[..size]);
                                    println!("Received message: {}", received);

                                    // Update the received message
                                    let mut received_message = received_message.lock().unwrap();
                                    *received_message = received.to_string();

                                    // Check if the message starts with "tx,"
                                    if received.starts_with("tx,") {
                                        // Parse the amount from the message
                                        let parts: Vec<&str> = received.split(',').collect();
                                        if parts.len() == 2 {
                                            if let Ok(amount) = parts[1].parse::<f32>() {
                                                // Update the balance
                                                let mut balance = balance.lock().unwrap();
                                                *balance -= amount;
                                                println!("Updated balance: {}", *balance);
                                            }
                                        }

                                        // Clear the received message
                                        *received_message = String::new();
                                        println!("Cleared received message due to 'tx,' prefix.");
                                    }

                                    // Respond back to the sender
                                    stream.write_all(b"Received your message").unwrap();
                                }
                                Err(e) => {
                                    eprintln!("Failed to read from stream: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to accept connection: {}", e);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Failed to start listener: {}", e);
            }
        }
    });
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
    new_ip: String,  // 新增的 IP 字段
    new_port: String,  // 新增的 Port 字段
    saved_bank_ip: Option<String>,
    saved_bank_port: Option<String>,
    saved_your_ip: Option<String>,
    saved_your_port: Option<String>,
    saved_tx_ip: Option<String>,
    saved_tx_port: Option<String>,
    saved_new_ip: Option<String>,  // 新增的保存 IP 字段
    saved_new_port: Option<String>,  // 新增的保存 Port 字段
    balance: Arc<Mutex<f32>>,
    is_running: bool,
    status: Vec<String>,
    own_ip: String,
    own_port: String,
    received_message: Arc<Mutex<String>>,
}

impl MyApp {
    fn send_prestart(&mut self) {
        if self.saved_bank_ip.is_none() || self.saved_bank_port.is_none() {
            self.add_status("Bank IP or Port not set".to_string());
            return;
        }

        let ip = self.saved_bank_ip.as_ref().unwrap();
        let port = self.saved_bank_port.as_ref().unwrap();

        match send_and_receive_tcp(ip, port, "prestart") {
            Ok(response) => {
                self.add_status(format!("Prestart response: {}", response));
            }
            Err(err) => {
                eprintln!("Failed to send prestart: {}", err);
                self.add_status(format!("Failed to send prestart: {}", err));
            }
        }
    }

    fn handle_start(&mut self, amount_value: i32) {
        if self.saved_tx_ip.is_none() || self.saved_tx_port.is_none() {
            self.add_status("Transaction IP or Port not set".to_string());
            self.is_running = false;
            return;
        }
    
        let ip = self.saved_tx_ip.as_ref().unwrap();
        let port = self.saved_tx_port.as_ref().unwrap();
    
        // Send "start,amount" message to tx ip and port
        let message = format!("tx,{}", amount_value);
        match send_and_receive_tcp(ip, port, &message) {
            Ok(response) => {
                self.add_status(format!("tx response: {}", response));
            }
            Err(err) => {
                eprintln!("Failed to send prestart: {}", err);
                self.add_status(format!("Failed to send tx: {}", err));
            }
        }
    
        // Send the same message to the new IP and Port if they are set
        if let (Some(new_ip), Some(new_port)) = (&self.saved_new_ip, &self.saved_new_port) {
            match send_and_receive_tcp(new_ip, new_port, &message) {
                Ok(response) => {
                    self.add_status(format!("New IP response: {}", response));
                }
                Err(err) => {
                    eprintln!("Failed to send to new IP: {}", err);
                    self.add_status(format!("Failed to send to new IP: {}", err));
                }
            }
        }
    
        // First, lock balance to update it
        {
            let mut balance = self.balance.lock().unwrap();
            *balance -= amount_value as f32;
            println!("Updated balance: {}", *balance);
        } // Lock is released here
    
        // Send "success" message to bank without waiting for a response
        self.send_status_to_bank("success");
    
        self.is_running = false;
    
        // Clear the received message after handling
        {
            let mut received_message = self.received_message.lock().unwrap();
            *received_message = String::new();
        } // Lock is released here
    }
    
    
    fn send_status_to_bank(&mut self, status: &str) {
        if self.saved_bank_ip.is_none() || self.saved_bank_port.is_none() {
            self.add_status("Bank IP or Port not set".to_string());
            return;
        }
    
        let ip = self.saved_bank_ip.as_ref().unwrap();
        let port = self.saved_bank_port.as_ref().unwrap();
    
        let message = format!("{},{}", status, self.amount);
        if let Err(err) = send_tcp(ip, port, &message) {
            eprintln!("Failed to send status to bank: {}", err);
            self.add_status(format!("Failed to send status to bank: {}", err));
        }
    }
    

    fn add_status(&mut self, new_status: String) {
        self.status.push(new_status);
    }

    fn start_listener_thread(&mut self) {
        // Start listener on user's IP and Port
        let received_message = Arc::clone(&self.received_message);
        let balance = Arc::clone(&self.balance);
        start_listener(self.own_ip.clone(), self.own_port.clone(), received_message, balance);
        self.add_status(format!("Listening on {}:{}", self.own_ip, self.own_port));
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.label("Threshold Wallet: User A");
            ui.add_space(20.0);
            ui.label(format!("Balance: ￥{:.2}", *self.balance.lock().unwrap()));
            ui.add_space(20.0);

            // First row: Bank IP and Bank Port + Confirm button
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

            // Second row: Prestart button
            if ui.add_sized(egui::vec2(80.0, 18.0), egui::Button::new("Prestart")).clicked() {
                self.send_prestart();
            }

            // Third row: Your IP and Port + Start Listen button
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

            // Fourth row: Received message
            ui.horizontal(|ui| {
                ui.label("Received Message:");
                let received_message = self.received_message.lock().unwrap();
                ui.label(&*received_message);
            });

            // Fifth row: Tx IP and Tx Port + Amount + Start button
            ui.horizontal(|ui| {
                ui.label("Tx IP:");
                ui.add_sized(egui::vec2(120.0, 18.0), egui::TextEdit::singleline(&mut self.tx_ip));
                ui.label("Tx Port:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.tx_port));
                ui.label("Amount:");
                ui.add_sized(egui::vec2(60.0, 18.0), egui::TextEdit::singleline(&mut self.amount));
                
                // Check if the received message is empty
                let is_start_button_enabled = !self.received_message.lock().unwrap().is_empty();
                if ui.add_enabled(is_start_button_enabled, egui::Button::new("Start")).clicked() {
                    self.saved_tx_ip = Some(self.tx_ip.clone());
                    self.saved_tx_port = Some(self.tx_port.clone());

                    let amount_value: i32 = self.amount.parse().unwrap_or(0);
                    self.handle_start(amount_value);
                }
            });

            // Sixth row: New IP and New Port
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

            // Display status messages
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
        new_ip: String::new(),  // 初始化新的 IP 字段
        new_port: String::new(),  // 初始化新的 Port 字段
        saved_bank_ip: None,
        saved_bank_port: None,
        saved_your_ip: None,
        saved_your_port: None,
        saved_tx_ip: None,
        saved_tx_port: None,
        saved_new_ip: None,  // 初始化新的保存 IP 字段
        saved_new_port: None,  // 初始化新的保存 Port 字段
        balance: Arc::new(Mutex::new(1000.0)), // Initial balance
        is_running: false,
        status: Vec::new(),
        own_ip: String::new(),
        own_port: String::new(),
        received_message: Arc::new(Mutex::new(String::new())),
    };

    eframe::run_native("Threshold Wallet", eframe::NativeOptions::default(), Box::new(|_cc| Ok(Box::<MyApp>::new(app))));
}