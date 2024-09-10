use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rand::Rng;

use tonic::{transport::Server, Request, Response, Status};

use zkp_auth::auth_server::{Auth, AuthServer};
use zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

// public generators
const G: u64 = 12;
const H: u64 = 15;
// prime number
const P: u64 = 1048559; //2^20 - 17

#[derive(Debug, Default, Clone)]
pub struct MyAuth {
    // username, (y1, y2)
    users: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    // auth_id, (username, r1, r2, c)
    challenges: Arc<Mutex<HashMap<String, (String, u64, u64, u64)>>>,
}

impl MyAuth {
    pub fn new() -> Self {
        MyAuth {
            users: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_user(&self, username: String, y1: u64, y2: u64) -> Result<(), String> {
        let mut users = self.users.lock().map_err(|_| "Failed to lock users")?;
        users.insert(username, (y1, y2));
        Ok(())
    }

    pub fn create_challenge(&self, username: &str, r1: u64, r2: u64) -> Result<(String, u64), String> {
        let users = self.users.lock().map_err(|_| "Failed to lock users")?;

        // check if user exists
        if !users.contains_key(username) {
            return Err("User not found".to_string());
        }

        let auth_id = format!("{:x}", rand::random::<u64>());
        // generate random challenge c
        let c = rand::thread_rng().gen_range(0..P);
        let mut challenges = self.challenges.lock().map_err(|_| "Failed to lock challenges")?;

        challenges.insert(auth_id.clone(), (username.to_string(), r1, r2, c));
        Ok((auth_id, c))
    }

    pub fn verify(&self, auth_id: &str, s: u64) -> Result<String, String> {
        let mut challenges = self.challenges.lock().map_err(|_| "Failed to lock challenges")?;
        // remove & retrieve one-time use challenge
        let (username, r1, r2, c) = challenges.remove(auth_id).ok_or("Challenge not found")?;

        let users = self.users.lock().map_err(|_| "Failed to lock users")?;
        // retrieve y1 & y2 from user
        let &(y1, y2) = users.get(&username).ok_or("User not found")?;
        // println!("y1: {} y2: {}", y1, y2);

        let v1 = (mod_pow(G, s, P) * mod_pow(y1, c, P)) % P;
        let v2 = (mod_pow(H, s, P) * mod_pow(y2, c, P)) % P;
        // println!("v1: {} v2: {}", v1, v2);
        // println!("r1: {} r2: {}", r1, r2);
        // println!("s: {}", s);
        // println!("c: {}", c);

        if v1 == r1 && v2 == r2 {
            Ok(format!("{:x}", rand::random::<u64>()))
        } else {
            Err("Authentication Failure".to_string())
        }
    }
}

#[tonic::async_trait]
impl Auth for MyAuth {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner().clone();

        self.register_user(req.user.clone(), req.y1, req.y2)
            .map_err(|e| Status::internal(e));

        Ok(Response::new(RegisterResponse{
            message: format!("New User Registered! {}", req.user),
        }))
    }

    async fn create_authentication_challenge(
        &self, 
        request: Request<AuthenticationChallengeRequest>,) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let req = request.into_inner();
        let (auth_id, c) = self.create_challenge(&req.user, req.r1, req.r2)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(AuthenticationChallengeResponse { auth_id, c }))
    }

    async fn verify_authentication(
        &self, 
        request: Request<AuthenticationAnswerRequest>,) -> 
        Result<Response<AuthenticationAnswerResponse>, Status> {
        let req = request.into_inner();
        let session_id = self.verify(&req.auth_id, req.s)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(AuthenticationAnswerResponse { session_id }))
    }
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


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let auth = MyAuth::default();

    Server::builder()
        .add_service(AuthServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}