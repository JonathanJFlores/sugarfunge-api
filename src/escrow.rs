use crate::state::*;
use crate::sugarfunge;
use crate::util::*;
use crate::user;
use crate::config::Config;
use actix_web::{error, web, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use subxt::PairSigner;
use actix_web_middleware_keycloak_auth::KeycloakClaims;


#[derive(Serialize, Deserialize)]
pub struct CreateEscrowInput {
    owner: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreateEscrowOutput {
    escrow: String,
    operator: String,
    owner: String,
}

pub async fn create_escrow(
    data: web::Data<AppState>,
    req: web::Json<CreateEscrowInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>,
    env: web::Data<Config>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub, env).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.owner).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                .tx()
                .escrow()
                .create_escrow(
                    to,
                )
                .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::escrow::events::Created>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(CreateEscrowOutput {
                        escrow: event.escrow.to_string(),
                        operator: event.operator.to_string(),
                        owner: event.owner.to_string(),
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::escrow::events::Created"),
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
pub struct RefundAssetsInput {
    escrow: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefundAssetsOutput {
    escrow: String,
    operator: String,
    owner: String,
}

pub async fn refund_assets(
    data: web::Data<AppState>,
    req: web::Json<RefundAssetsInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>,
    env: web::Data<Config>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub, env).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.escrow).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                .tx()
                .escrow()
                .refund_assets(
                    to,
                )
                .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::escrow::events::Refund>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(RefundAssetsOutput {
                        escrow: event.escrow.to_string(),
                        operator: event.operator.to_string(),
                        owner: event.owner.to_string(),
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::escrow::events::Refund"),
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
pub struct DepositAssetsInput {
    escrow: String,
    class_id: u64,
    asset_ids: Vec<u64>,
    amounts: Vec<u128>,
}

#[derive(Serialize, Deserialize)]
pub struct DepositAssetsOutput {
    escrow: String,
    operator: String,
    owner: String,
}

pub async fn deposit_assets(
    data: web::Data<AppState>,
    req: web::Json<DepositAssetsInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>,
    env: web::Data<Config>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub, env).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.escrow).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                .tx()
                .escrow()
                .deposit_assets(
                    to,
                    req.class_id,
                    req.asset_ids.clone(),
                    req.amounts.clone(),
                )
                .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::escrow::events::Deposit>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(DepositAssetsOutput {
                        escrow: event.escrow.to_string(),
                        operator: event.operator.to_string(),
                        owner: event.owner.to_string(),
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::escrow::events::Deposit"),
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
