use eframe::{egui, App};
use tokio::sync::{Mutex};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // 确保引入必要的异步IO功能
use sqlx::mysql::MySqlPool;
use dotenv::dotenv; // 导入 dotenv 库

#[derive(Default)]
struct MyApp {
    bank_ip: String,
    bank_port: String,
    regulator_ip: String,
    regulator_port: String,
    saved_regulator_ip: Option<String>,  // 新增字段保存 regulator_ip
    saved_regulator_port: Option<String>, // 新增字段保存 regulator_port
    status: String,
    db_pool: Option<MySqlPool>,
}

impl MyApp {
    // 启动 TCP 服务器并处理消息
    async fn start_tcp_server(
        ip: String,
        port: String,
        status: Arc<Mutex<String>>,
        db_pool: Option<MySqlPool>,
        regulator_ip: Option<String>,  // 使用 Option<String> 类型接收 regulator_ip
        regulator_port: Option<String>,  // 使用 Option<String> 类型接收 regulator_port
    ) {
        println!("Starting TCP listener on {}:{}", ip, port);
        
        let listener = TcpListener::bind(format!("{}:{}", ip, port))
            .await
            .expect("Failed to bind to address");

        let status_lock = status.lock().await;
        println!("Server is listening: {}", *status_lock);

        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            println!("New connection: {:?}", socket.peer_addr().unwrap());

            // 处理接收到的消息
            let db_pool = db_pool.clone();
            let regulator_ip_clone = regulator_ip.clone();  // 克隆 regulator_ip
            let regulator_port_clone = regulator_port.clone();  // 克隆 regulator_port
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let msg = String::from_utf8_lossy(&buf[..n]);
                    println!("Received message: {}", msg);

                    if msg.trim() == "prestart" {
                        if let Some(pool) = &db_pool {
                            // 如果有保存的 regulator_ip 和 regulator_port，则使用它们
                            let result = MyApp::handle_prestart(pool, regulator_ip_clone.clone(), regulator_port_clone.clone()).await;
                            socket.write_all(result.as_bytes()).await.unwrap();
                        }
                    } else if msg.starts_with("success,") {
                        let parts: Vec<&str> = msg.split(';').collect();
                        if let Some(pool) = &db_pool {
                            // let amount_str = msg.trim_start_matches("success,");
                            if let Ok(amount) = parts[1].parse::<f64>() {
                                MyApp::handle_success(pool, amount).await;
                                let message = format!("tx,{}",amount);
                                if let Err(e) = MyApp::send_to_regulator("127.0.0.1".to_string(), "8083".to_string(), message.clone()).await {
                                    eprintln!("Failed to send success message to 127.0.0.1:8083: {}", e);
                                }
                                if let Err(e) = MyApp::send_to_regulator("127.0.0.1".to_string(), "8084".to_string(), message.clone()).await {
                                    eprintln!("Failed to send success message to 127.0.0.1:8084: {}", e);
                                }
                                if let Err(e) = MyApp::send_to_regulator("127.0.0.1".to_string(), "8085".to_string(), message.clone()).await {
                                    eprintln!("Failed to send success message to 127.0.0.1:8085: {}", e);
                                }
                            }
                        }
                    } else if msg.trim() == "fail" {
                        if let Some(pool) = &db_pool {
                            MyApp::handle_fail(pool).await;
                        }
                    }
                }
            });
        }
    }

    // 处理 prestart 消息，更新数据库并返回交易ID
    async fn handle_prestart(pool: &MySqlPool, regulator_ip: Option<String>, regulator_port: Option<String>) -> String {
        // 检查是否有未完成的交易
        let row = sqlx::query!("SELECT COUNT(*) AS count FROM transactions WHERE completed = 0")
            .fetch_one(pool)
            .await
            .expect("Failed to check for pending transactions");

        if row.count > 0 {
            // 如果有未完成的交易，返回 fail
            return "fail".to_string();
        }

        // 如果没有未完成的交易，执行以下操作

        // 查找最大交易ID
        let row = sqlx::query!("SELECT MAX(id) AS max_id FROM transactions")
            .fetch_one(pool)
            .await
            .expect("Failed to fetch max transaction ID");

        let new_id = row.max_id.unwrap_or(0) + 1;

        // 插入新的交易记录
        sqlx::query!("INSERT INTO transactions (id, amount, completed) VALUES (?, ?, ?)",
            new_id, 0, 0)
            .execute(pool)
            .await
            .expect("Failed to insert new transaction");

        // 获取保存的 regulator_ip 和 regulator_port
        if let (Some(reg_ip), Some(reg_port)) = (regulator_ip, regulator_port) {
            // 发送消息到 regulator
            let message = format!("prestart,{}", new_id);
            
            if let Err(e) = MyApp::send_to_regulator(reg_ip, reg_port, message).await {
                eprintln!("Failed to send message to regulator: {}", e);
            }
        }

        // 返回 success
        "success".to_string()
    }

    // 处理成功消息
    async fn handle_success(pool: &MySqlPool, amount: f64) {
        // 更新数据库中最新的交易记录，将 completed 设为 1 并更新 amount
        let row = sqlx::query!("SELECT id FROM transactions WHERE completed = 0 ORDER BY id DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("Failed to fetch latest transaction");

        let transaction_id = row.id;

        sqlx::query!("UPDATE transactions SET completed = 1, amount = ? WHERE id = ?",
            amount, transaction_id)
            .execute(pool)
            .await
            .expect("Failed to update transaction");

        println!("Transaction {} completed successfully with amount: {}", transaction_id, amount);

        // 新增：向 127.0.0.1:9091 发送 "success," 消息
        let message = format!("success,{}", amount);
        if let Err(e) = MyApp::send_to_regulator("127.0.0.1".to_string(), "9091".to_string(), message).await {
            eprintln!("Failed to send success message to 127.0.0.1:9091: {}", e);
        }
    }

    // 处理失败消息
    async fn handle_fail(pool: &MySqlPool) {
        // 更新数据库中最新的交易记录，将 completed 设为 1
        let row = sqlx::query!("SELECT id FROM transactions WHERE completed = 0 ORDER BY id DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .expect("Failed to fetch latest transaction");

        let transaction_id = row.id;

        sqlx::query!("UPDATE transactions SET completed = 1 WHERE id = ?",
            transaction_id)
            .execute(pool)
            .await
            .expect("Failed to update transaction");

        println!("Transaction {} failed", transaction_id);
    }

    // 向 regulator 发送消息
    async fn send_to_regulator(ip: String, port: String, message: String) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", ip, port);
        println!("{}",addr);
        let mut stream = TcpStream::connect(addr).await?;

        // 发送消息
        stream.write_all(message.as_bytes()).await?;
        Ok(())
    }
}

impl App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Bank");

            // Bank IP and Port inputs with Start Listen button
            ui.horizontal(|ui| {
                ui.label("Bank IP:");
                ui.add(egui::TextEdit::singleline(&mut self.bank_ip).desired_width(75.0));
                ui.label("Bank Port:");
                ui.add(egui::TextEdit::singleline(&mut self.bank_port).desired_width(50.0));
                if ui.button("Start Listen").clicked() {
                    let ip = self.bank_ip.clone();
                    let port = self.bank_port.clone();
                    self.status = "Listening for connections...".to_string();

                    let status = Arc::new(Mutex::new(self.status.clone()));
                    let db_pool = self.db_pool.clone();  // Passing database pool

                    let regulator_ip = self.saved_regulator_ip.clone();  // 使用保存的 regulator_ip
                    let regulator_port = self.saved_regulator_port.clone();  // 使用保存的 regulator_port

                    // 在点击按钮时启动异步任务
                    tokio::spawn(async move {
                        MyApp::start_tcp_server(ip, port, status, db_pool, regulator_ip, regulator_port).await;
                    });
                }
            });

            // Regulator IP and Port inputs with Confirm button
            ui.horizontal(|ui| {
                ui.label("Regulator IP:");
                ui.add(egui::TextEdit::singleline(&mut self.regulator_ip).desired_width(75.0));
                ui.label("Regulator Port:");
                ui.add(egui::TextEdit::singleline(&mut self.regulator_port).desired_width(50.0));
                if ui.button("Confirm").clicked() {
                    // 保存用户输入的 regulator_ip 和 regulator_port
                    self.saved_regulator_ip = Some(self.regulator_ip.clone());
                    self.saved_regulator_port = Some(self.regulator_port.clone());
                    println!("Regulator IP: {}, Regulator Port: {}", self.regulator_ip, self.regulator_port);
                }
            });

            // Status display
            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.label(&self.status);
            });
        });
    }
}

#[tokio::main]
async fn main() {
    // 加载 .env 文件
    dotenv().ok();

    // 从环境变量获取数据库 URL
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");

    // 设置数据库连接池
    let db_pool = MySqlPool::connect(&db_url)
        .await
        .expect("Failed to connect to the database");

    let app = MyApp {
        db_pool: Some(db_pool),
        ..Default::default()
    };
    
    let options = eframe::NativeOptions {
        drag_and_drop_support: true,
        ..Default::default()
    };
    eframe::run_native("Bank", options, Box::new(|_cc| Box::new(app)));
}
