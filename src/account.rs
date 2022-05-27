use crate::state::*;
use crate::sugarfunge;
use crate::user::get_sugarfunge_token;
use crate::util::*;
use crate::user;
use crate::config::Config;
use actix_web::http::header;
use actix_web::{error, web, HttpRequest, http::StatusCode, HttpResponse};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_core::Pair;
use std::str::FromStr;
use subxt::sp_runtime::traits::IdentifyAccount;
use subxt::PairSigner;
use actix_web_middleware_keycloak_auth::KeycloakClaims;

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAccountOutput {
    seed: String,
    account: String,
}

/// Generate a unique seed and its associated account
pub async fn create(_req: HttpRequest) -> error::Result<HttpResponse> {
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let seed = hex::encode(seed);
    let seed = format!("//{}", seed);
    let pair = get_pair_from_seed(&seed)?;
    let account = pair.public().into_account();
    Ok(HttpResponse::build(StatusCode::OK).json(CreateAccountOutput {
        seed,
        account: format!("{}", account),
    }))
}

#[derive(Serialize, Deserialize)]
pub struct FundAccountInput {
    to: String,
    amount: u128,
}

#[derive(Serialize, Deserialize)]
pub struct FundAccountOutput {
    from: String,
    to: String,
    amount: u128,
}

/// Fund a given account with amount
pub async fn fund(
    data: web::Data<AppState>,
    req: web::Json<FundAccountInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>,
    env: web::Data<Config>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub, env).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let account = sp_core::sr25519::Public::from_str(&req.to).map_err(map_account_err)?;
                let account = sp_core::crypto::AccountId32::from(account);
                let account = subxt::sp_runtime::MultiAddress::Id(account);
                let amount_input = req.amount;
                let api = data.api.lock().unwrap();
                let result = api
                    .tx()
                    .balances()
                    .transfer(account, amount_input)
                    .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::balances::events::Transfer>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(FundAccountOutput {
                        from: event.from.to_string(),
                        to: event.to.to_string(),
                        amount: event.amount,
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::balances::events::Transfer"),
                    })),
                }

            } else {
                Ok(HttpResponse::BadRequest().json(RequestError {
                    message: json!("Not found user Attributes"),
                }))
            }
        },
        Err(_) => Ok(HttpResponse::BadRequest().json(RequestError {
            message: json!("Failed to find user::getAttributes"),
        }))
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccountBalanceInput {
    account: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountBalanceOutput {
    balance: u128,
}

/// Get balance for given account
pub async fn balance(
    data: web::Data<AppState>,
    req: web::Json<AccountBalanceInput>,
) -> error::Result<HttpResponse> {
    let account = sp_core::sr25519::Public::from_str(&req.account).map_err(map_account_err)?;
    let account = sp_core::crypto::AccountId32::from(account);
    let api = data.api.lock().unwrap();
    let result = api.storage().system().account(account, None).await;
    let data = result.map_err(map_subxt_err)?;
    Ok(HttpResponse::Ok().json(AccountBalanceOutput {
        balance: data.data.free,
    }))
}

#[derive(Serialize, Deserialize)]
pub struct TransferAccountInput {
    to: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferAccountOutput {
    error: Option<String>,
    message: String
}

pub async fn transfer(
    req: web::Json<TransferAccountInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>,
    env: web::Data<Config>
) -> error::Result<HttpResponse> {
    let config = env.clone();
    let env_aux = env.clone();
    match user::get_seed(&claims.sub, env).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                match get_sugarfunge_token(env_aux).await {
                    Ok(response) => {
                        
                        let awc_client = awc::Client::new();
                        let endpoint = format!("{}/auth/admin/realms/{}/users/{}", config.keycloak_host, config.keycloak_realm, &claims.sub); 

                        let attributes = json!({
                            "attributes": ""
                        });
            
                        let user_response = awc_client.put(endpoint)
                            .append_header((header::ACCEPT, "application/json"), )
                            .append_header((header::CONTENT_TYPE, "application/json"))
                            .append_header((header::AUTHORIZATION, "Bearer ".to_string() + &response.access_token))
                            .send_json(&attributes)
                            .await;
            
                        match user_response {
                            Ok(user_response) => {
                                if let StatusCode::NO_CONTENT = user_response.status() {
                                    
                                    let awc_client = awc::Client::new();
                                    let endpoint = format!("{}/auth/admin/realms/{}/users/{}", config.keycloak_host, config.keycloak_realm, req.to); 

                                    let attributes = json!({
                                        "attributes": {
                                            "user-seed": [
                                                user_seed
                                            ]
                                        }
                                    });
                        
                                    let receiver_response = awc_client.put(endpoint)
                                        .append_header((header::ACCEPT, "application/json"), )
                                        .append_header((header::CONTENT_TYPE, "application/json"))
                                        .append_header((header::AUTHORIZATION, "Bearer ".to_string() + &response.access_token))
                                        .send_json(&attributes)
                                        .await;

                                    match receiver_response {
                                        Ok(receiver_response) => {
                                            if let StatusCode::NO_CONTENT = receiver_response.status() {
                                                Ok(HttpResponse::Ok().json(
                                                    TransferAccountOutput {
                                                        error: None,
                                                        message: "Attribute insert to user attributes".to_string()
                                                    }
                                                ))
                                            } 
                                            else {
                                                Ok(HttpResponse::BadRequest().json(RequestError {
                                                    message: json!("Failed to find user::getAttributes"),
                                                }))
                                            }
                                        }
                                        Err(_e) => {
                                            Ok(HttpResponse::BadRequest().json(RequestError {
                                                    message: json!("Failed to find user::getAttributes"),
                                                }))
                                            }                                        
                                    }    
                                                                       
                                } else {
                                    Ok(HttpResponse::BadRequest().json(RequestError {
                                        message: json!("Failed to find user::getAttributes"),
                                    }))
                                }
                            }                
                            Err(_e) => {
                            Ok(HttpResponse::BadRequest().json(RequestError {
                                    message: json!("Failed to find user::getAttributes"),
                                }))
                            }
                        }

                    }
                    Err(_e) => {
                        Ok(HttpResponse::BadRequest().json(RequestError {
                                message: json!("Failed to find user::getAttributes"),
                            }))
                        }
                }
            } else {
                Ok(HttpResponse::BadRequest().json(RequestError {
                    message: json!("Not found user Attributes"),
                }))
            }
        },
        Err(_) => Ok(HttpResponse::BadRequest().json(RequestError {
            message: json!("Failed to find user::getAttributes"),
        }))
    }
}