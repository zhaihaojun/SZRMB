use eframe::egui::{CentralPanel, Context};
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

struct App {
    balance: Arc<Mutex<i32>>,
}

impl App {
    fn new() -> Self {
        App {
            balance: Arc::new(Mutex::new(1000)),
        }
    }

    fn update_balance(&self, amount: i32) {
        let mut balance = self.balance.lock().unwrap();
        *balance -= amount;
    }

    fn get_balance(&self) -> i32 {
        *self.balance.lock().unwrap()
    }
}

#[tokio::main]
async fn main() {
    let app = Arc::new(App::new());
    let (tx, mut rx): (mpsc::Sender<i32>, mpsc::Receiver<i32>) = mpsc::channel(32);

    // Start TCP listener in a separate task
    let app_clone = Arc::clone(&app);
    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9091").await.unwrap();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                if msg.starts_with("success,") {
                    if let Some(amount_str) = msg.split(',').nth(1) {
                        if let Ok(amount) = amount_str.parse::<i32>() {
                            tx.send(amount).await.unwrap();
                        }
                    }
                }
            });
        }
    });

    // Start GUI
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Receiver App",
        options,
        Box::new(|_cc| Box::new(MyEguiApp::new(app, rx))),
    );
}

struct MyEguiApp {
    app: Arc<App>,
    rx: mpsc::Receiver<i32>,
}

impl MyEguiApp {
    fn new(app: Arc<App>, rx: mpsc::Receiver<i32>) -> Self {
        MyEguiApp { app, rx }
    }
}

impl eframe::App for MyEguiApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Check the receiver for new balance updates
        if let Ok(amount) = self.rx.try_recv() {
            self.app.update_balance(amount);
        }

        // Draw the UI
        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Receiver");
            ui.label(format!("Balance: {}", self.app.get_balance()));
        });
    }
}
