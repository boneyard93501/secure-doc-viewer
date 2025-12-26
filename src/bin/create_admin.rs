use docsend::{Config, db};
use sqlx::postgres::PgPoolOptions;
use std::io::{self, Write};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenvy::dotenv().ok();
    
    println!("=== DocSend Admin Creator ===\n");

    // Check for command line args for non-interactive mode
    let args: Vec<String> = std::env::args().collect();
    
    let (email, password) = if args.len() == 3 {
        // Non-interactive: docsend-admin <email> <password>
        (args[1].clone(), args[2].clone())
    } else if args.len() == 1 {
        // Interactive mode
        let email = read_line("Admin email: ");
        println!("(Note: Password will be visible)");
        let password = read_line("Password: ");
        let password_confirm = read_line("Confirm password: ");
        
        if password != password_confirm {
            eprintln!("Error: Passwords do not match");
            std::process::exit(1);
        }
        
        (email, password)
    } else {
        eprintln!("Usage: docsend-admin [<email> <password>]");
        eprintln!("  Interactive mode: docsend-admin");
        eprintln!("  Non-interactive:  docsend-admin admin@example.com mypassword");
        std::process::exit(1);
    };

    if email.is_empty() {
        eprintln!("Error: Email cannot be empty");
        std::process::exit(1);
    }

    if password.len() < 8 {
        eprintln!("Error: Password must be at least 8 characters");
        std::process::exit(1);
    }

    // Load config
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
    let config = Config::load(&config_path)?;

    // Get database password from env
    let db_password = std::env::var("DB_PASSWORD").expect("DB_PASSWORD must be set");
    let database_url = config.database.connection_string(&db_password);

    // Connect to database
    println!("Connecting to database...");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    println!("Connected!");

    // Check if admin already exists
    if let Ok(Some(_)) = db::get_admin_by_email(&pool, &email).await {
        eprintln!("Error: Admin with email '{}' already exists", email);
        std::process::exit(1);
    }

    // Hash password
    println!("Hashing password...");
    let password_hash = hash_password(&password).map_err(|e| format!("Failed to hash password: {}", e))?;

    // Create admin
    println!("Creating admin...");
    let admin = db::create_admin(&pool, &email, &password_hash).await?;

    println!("\n✓ Admin created successfully!");
    println!("  ID: {}", admin.id);
    println!("  Email: {}", admin.email);
    println!("  Created: {:?}", admin.created_at);

    Ok(())
}
