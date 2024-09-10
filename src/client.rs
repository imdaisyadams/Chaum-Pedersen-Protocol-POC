use rand::distributions::uniform::UniformSampler;
use tonic::{client, Request};
use tonic::server::UnaryService;
use zkp_auth::auth_client::AuthClient;
use zkp_auth::{RegisterRequest, AuthenticationChallengeRequest, AuthenticationAnswerRequest};
use rand::Rng;
use std::io::{self, Write};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

// public generators, same size cycle within P
const G: u64 = 12;
const H: u64 = 15;
// largest prime factor of P - 1
const Q: u64 = 74897;
// prime number
const P: u64 = 1048559; //2^20 - 17

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AuthClient::connect("http://[::1]:50051").await?;

    loop {
        println!("\n Welcome to Chaum-Pederson ZK Protocol");
        println!("\n Choose an action:");
        println!("\n 1. Register");
        println!("\n 2. Login");
        println!("\n 3. Exit");
        println!("\n Enter your choice (1-3)");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => register(&mut client).await?,
            "2" => login(&mut client).await?,
            "3" => break,
            _ => println!("Invalid choice. Please try again"),
        }
    }

    Ok(())
}


async fn register(client: &mut AuthClient<tonic::transport::Channel>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Enter Username: ");
    io::stdout().flush();
    let mut username = String::new();
    io::stdin().read_line(&mut username);
    let username = username.trim().to_string();

    println!("Enter your password (x) between 1 and {}:", P-1);
    io::stdout().flush();
    let mut x = String::new();
    io::stdin().read_line(&mut x);
    let x: u64 = x.trim().parse()?;

    if x <= 0 || x >= P {
        println!("Sorry, please enter a password between 1 and {}", P-1);
        return Ok(());
    }

    // compute y1 & y2 with users password
    let y1 = mod_pow(G, x, P);
    let y2 = mod_pow(H, x, P);

    // send registration request to server
    let request = tonic::Request::new(RegisterRequest {
        user: username.to_string(),
        y1,
        y2,
    });

    let response = client.register(request).await?;
    println!("Registration response: {:?}", response);
    println!("Registration Successful! Please don't share your password with anyone.");

    Ok(())
}


async fn login(client: &mut AuthClient<tonic::transport::Channel>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Welcome back!");
    println!("Enter username:");
    io::stdout().flush();
    let mut username = String::new();
    io::stdin().read_line(&mut username);
    let username = username.trim().to_string();

    println!("Enter your password:");
    io::stdout().flush();
    let mut x = String::new();
    io::stdin().read_line(&mut x);
    let x: u64 = x.trim().parse()?;

    // create challenge
    // k is a random temporary secret, not using x again
    let k = rand::thread_rng().gen_range(1..P);
    // r1 & r2 are client's commitments using k
    let r1 = mod_pow(G, k, P);
    let r2 = mod_pow(H, k, P);

    // send authentication request to server
    let request = tonic::Request::new(AuthenticationChallengeRequest {
        user: username,
        r1,
        r2, 
    });

    let response = client.create_authentication_challenge(request).await?;
    println!("Challenge received: {:?}", response);

    let auth_id = response.get_ref().auth_id.clone();
    // retrieve challenge c sent by server
    let c = response.get_ref().c;

    let temp = c * x % Q;
    //Rust subtract operates mod 2^64, so temp makes sure we only do math with mod Q
    // s = k - cx mod Q
    let s = k - temp % Q;

    let verify_request = tonic::Request::new(AuthenticationAnswerRequest{
        auth_id,
        s,
    });

    match client.verify_authentication(verify_request).await {
        Ok(response) => {
            println!("You're logged in!");
            println!("Session ID: {}", response.into_inner().session_id);
        }
        Err(status) => {
            println!("Authentication failed: {}", status.message());
        }
    }

    Ok(())
}

// modular exponentiation
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    if modulus == 1 { return 0 }
    let mut result = 1;
    base = base % modulus;
    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base % modulus;
        }
        exp = exp >> 1;
        base = base * base % modulus
    }
    result
}