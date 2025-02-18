use eframe::egui;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sqlx::{Pool, MySql};
use dotenv::dotenv;
use std::env;
use std::sync::{Arc, Mutex};

struct App {
    ip: String,
    port: String,
    status: String,
    received_message: Arc<Mutex<String>>,
    p1_ip: String,
    p1_port: String,
    p2_ip: String,
    p2_port: String,
    p3_ip: String,
    p3_port: String,
    participant1: String,
    participant2: String,
    pool: Option<Pool<MySql>>,
}

impl Default for App {
    fn default() -> Self {
        App {
            ip: String::new(),
            port: String::new(),
            status: String::new(),
            received_message: Arc::new(Mutex::new(String::new())),
            p1_ip: String::new(),
            p1_port: String::new(),
            p2_ip: String::new(),
            p2_port: String::new(),
            p3_ip: String::new(),
            p3_port: String::new(),
            participant1: String::new(),
            participant2: String::new(),
            pool: None,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Regulator Interface");

            // Regulator IP and Port inputs
            ui.horizontal(|ui| {
                ui.label("Regulator IP:");
                ui.add(egui::TextEdit::singleline(&mut self.ip).desired_width(100.0));
                ui.label("Regulator Port:");
                ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(100.0));
            });

            // Start Listen Button
            if ui.button("Start Listen").clicked() {
                if self.ip.is_empty() || self.port.is_empty() {
                    self.status = String::from("Please provide both IP and Port.");
                } else {
                    let addr = format!("{}:{}", self.ip, self.port);
                    self.status = String::from("Starting listener...");

                    // Clone the Arc<Mutex<String>> to pass it to the async task
                    let received_message = Arc::clone(&self.received_message);

                    // Spawn the async task using tokio::spawn
                    tokio::spawn(async move {
                        if let Err(e) = start_listening(&addr, received_message).await {
                            eprintln!("Error: {}", e);
                        }
                    });
                }
            }

            // Display received message
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Received Message:");
                let received_message = self.received_message.lock().unwrap();
                ui.label(&*received_message);
            });

            // P1, P2, P3 IP and Port inputs
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("P1 IP:");
                ui.add(egui::TextEdit::singleline(&mut self.p1_ip).desired_width(100.0));
                ui.label("P1 Port:");
                ui.add(egui::TextEdit::singleline(&mut self.p1_port).desired_width(100.0));
            });
            ui.horizontal(|ui| {
                ui.label("P2 IP:");
                ui.add(egui::TextEdit::singleline(&mut self.p2_ip).desired_width(100.0));
                ui.label("P2 Port:");
                ui.add(egui::TextEdit::singleline(&mut self.p2_port).desired_width(100.0));
            });
            ui.horizontal(|ui| {
                ui.label("P3 IP:");
                ui.add(egui::TextEdit::singleline(&mut self.p3_ip).desired_width(100.0));
                ui.label("P3 Port:");
                ui.add(egui::TextEdit::singleline(&mut self.p3_port).desired_width(100.0));
            });

            // Confirm Button
            if ui.button("Confirm").clicked() {
                self.status = format!(
                    "P1: {}:{}\nP2: {}:{}\nP3: {}:{}",
                    self.p1_ip, self.p1_port, self.p2_ip, self.p2_port, self.p3_ip, self.p3_port
                );
            }

            // Participants input and Start Button
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Participate 1:");
                ui.add(egui::TextEdit::singleline(&mut self.participant1).desired_width(50.0));
                ui.label("Participate 2:");
                ui.add(egui::TextEdit::singleline(&mut self.participant2).desired_width(50.0));
            });

            // Start Button for participants
            if ui.button("Start").clicked() {
                let participant1 = self.participant1.clone();
                let participant2 = self.participant2.clone();
                let received_message = self.received_message.lock().unwrap().clone();

                // Clone the necessary fields to pass to the async task
                let p1_ip = self.p1_ip.clone();
                let p1_port = self.p1_port.clone();
                let p2_ip = self.p2_ip.clone();
                let p2_port = self.p2_port.clone();
                let p3_ip = self.p3_ip.clone();
                let p3_port = self.p3_port.clone();

                if received_message.is_empty() {
                    self.status = String::from("Received message is empty, please wait for a message.");
                } else {
                    self.received_message.lock().unwrap().clear();

                    tokio::spawn(async move {
                        // Extract transaction ID from received message
                        let transaction_id: Option<i32> = received_message
                            .split(',')
                            .nth(1)
                            .and_then(|s| s.parse::<i32>().ok());

                        if let Some(transaction_id) = transaction_id {
                            insert_into_identity(transaction_id, &participant1, &participant2).await;
                        }

                        if participant1 == "A" || participant1 == "B" || participant1 == "C" {
                            send_start_message(&participant1, &participant2, &p1_ip, &p1_port, &p2_ip, &p2_port, &p3_ip, &p3_port).await;
                        }

                        if participant2 == "A" || participant2 == "B" || participant2 == "C" {
                            send_start_message(&participant2, &participant1, &p1_ip, &p1_port, &p2_ip, &p2_port, &p3_ip, &p3_port).await;
                        }
                    });
                }
            }

            // Status message
            ui.separator();
            ui.label(&self.status);
        });
    }
}

// Function to start listening
async fn start_listening(
    addr: &str,
    received_message: Arc<Mutex<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("Started listening on {}", addr);

    loop {
        let (mut socket, _) = listener.accept().await?;
        println!("Accepted connection from: {:?}", socket.peer_addr()?);

        let mut buf = vec![0; 1024];
        match socket.read(&mut buf).await {
            Ok(n) if n > 0 => {
                let message = String::from_utf8_lossy(&buf[..n]).to_string();
                println!("Received message: {}", message);

                // Update the received message
                let mut received_message = received_message.lock().unwrap();
                *received_message = message;
            }
            Ok(_) => {}
            Err(e) => {
                println!("Error reading from socket: {}", e);
            }
        }
    }
}

// Function to send a start message
async fn send_start_message(
    participant: &str,
    other_participant: &str,
    p1_ip: &str,
    p1_port: &str,
    p2_ip: &str,
    p2_port: &str,
    p3_ip: &str,
    p3_port: &str,
) {
    // 根据参与者确定目标地址
    let target_address = match participant {
        "A" => format!("{}:{}", p1_ip, p1_port),
        "B" => format!("{}:{}", p2_ip, p2_port),
        "C" => format!("{}:{}", p3_ip, p3_port),
        _ => {
            println!("Invalid participant");
            return;
        }
    };

    // 构造要发送的消息
    let message = format!("start,{}", other_participant);

    // 打印调试信息
    println!("Sending start message to participant: {} at {} with message: {}", participant, target_address, message);

    // 连接到目标地址并发送消息
    match TcpStream::connect(&target_address).await {
        Ok(mut stream) => {
            // 写入消息到目标地址
            if let Err(e) = stream.write_all(message.as_bytes()).await {
                eprintln!("Failed to send message: {}", e);
            } else {
                println!("Message sent to {}", target_address);
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", target_address, e);
        }
    }
}

// Function to insert into MySQL database using sqlx
async fn insert_into_identity(
    transaction_id: i32,
    participant1: &str,
    participant2: &str,
) {
    dotenv().ok(); // Load the environment variables from .env file
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL not set in .env");

    let pool = Pool::<MySql>::connect(&database_url).await.unwrap();
    let query = "INSERT INTO identity (id, participant1, participant2) VALUES (?, ?, ?)";
    sqlx::query(query)
        .bind(transaction_id)
        .bind(participant1)
        .bind(participant2)
        .execute(&pool)
        .await
        .unwrap();

    println!("Inserted into identity table: {}, {}", participant1, participant2);
}

#[tokio::main] // Use tokio::main to create a runtime
async fn main() {
    let app = App::default();
    let options = eframe::NativeOptions {
        drag_and_drop_support: true,
        initial_window_size: Some(egui::vec2(400.0, 600.0)),
        ..Default::default()
    };

    // Run the eframe app within the Tokio runtime
    eframe::run_native(
        "Regulator",
        options,
        Box::new(|_cc| Box::<App>::default()),
    );
}