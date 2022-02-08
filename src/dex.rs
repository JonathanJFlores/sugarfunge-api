use crate::state::*;
use crate::sugarfunge;
use crate::util::*;
use crate::user;
use actix_web::{error, web, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use subxt::PairSigner;
use sugarfunge::runtime_types::sugarfunge_primitives::CurrencyId;
use actix_web_middleware_keycloak_auth::KeycloakClaims;

#[derive(Serialize, Deserialize)]
pub struct Currency {
    class_id: u64,
    asset_id: u64,
}

#[derive(Deserialize)]
pub struct CreateDexInput {
    exchange_id: u32,
    currency: Currency,
    asset_class_id: u64,
    lp_class_id: u64, // liquidity pool id
}

#[derive(Serialize)]
pub struct CreateDexOutput {
    exchange_id: u32,
    who: String,
}

/// Create dex for currency and asset class
pub async fn create(
    data: web::Data<AppState>,
    req: web::Json<CreateDexInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let currency_id = CurrencyId(req.currency.class_id, req.currency.asset_id);
                let api = data.api.lock().unwrap();
                let result = api
                    .tx()
                    .dex()
                    .create_exchange(
                        req.exchange_id,
                        currency_id,
                        req.asset_class_id,
                        req.lp_class_id,
                    )
                    .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::dex::events::ExchangeCreated>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(CreateDexOutput {
                        exchange_id: event.exchange_id,
                        who: event.who.to_string(),
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
pub struct BuyAssetsInput {
    exchange_id: u32,
    asset_ids: Vec<u64>,
    asset_amounts_out: Vec<u128>,
    max_currency: u128,
    to: String,
}

#[derive(Serialize, Deserialize)]
pub struct BuyAssetsOutput {
    exchange_id: u32,
    who: String,
    to: String,
    asset_ids: Vec<u64>,
    asset_amounts_out: Vec<u128>,
    currency_amounts_in: Vec<u128>,
}

/// Buy assets with currency
pub async fn buy_assets(
    data: web::Data<AppState>,
    req: web::Json<BuyAssetsInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.to).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                    .tx()
                    .dex()
                    .buy_assets(
                        req.exchange_id,
                        req.asset_ids.clone(),
                        req.asset_amounts_out.clone(),
                        req.max_currency,
                        to,
                    )
                    .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::dex::events::CurrencyToAsset>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(BuyAssetsOutput {
                        exchange_id: event.exchange_id,
                        who: event.who.to_string(),
                        to: event.to.to_string(),
                        asset_ids: event.asset_ids,
                        asset_amounts_out: event.asset_amounts_out,
                        currency_amounts_in: event.currency_amounts_in,
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::dex::events::CurrencyToAsset"),
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
pub struct SellAssetsInput {
    exchange_id: u32,
    asset_ids: Vec<u64>,
    asset_amounts_in: Vec<u128>,
    min_currency: u128,
    to: String,
}

#[derive(Serialize, Deserialize)]
pub struct SellAssetsOutput {
    exchange_id: u32,
    who: String,
    to: String,
    asset_ids: Vec<u64>,
    asset_amounts_in: Vec<u128>,
    currency_amounts_out: Vec<u128>,
}

/// Sell assets for currency
pub async fn sell_assets(
    data: web::Data<AppState>,
    req: web::Json<SellAssetsInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.to).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                    .tx()
                    .dex()
                    .sell_assets(
                        req.exchange_id,
                        req.asset_ids.clone(),
                        req.asset_amounts_in.clone(),
                        req.min_currency,
                        to,
                    )
                    .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::dex::events::AssetToCurrency>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(SellAssetsOutput {
                        exchange_id: event.exchange_id,
                        who: event.who.to_string(),
                        to: event.to.to_string(),
                        asset_ids: event.asset_ids,
                        asset_amounts_in: event.asset_amounts_in,
                        currency_amounts_out: event.currency_amounts_out,
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::dex::events::CurrencyToAsset"),
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
pub struct AddLiquidityInput {
    to: String,
    exchange_id: u32,
    asset_ids: Vec<u64>,
    asset_amounts: Vec<u128>,
    max_currencies: Vec<u128>,
}

#[derive(Serialize, Deserialize)]
pub struct AddLiquidityOutput {
    exchange_id: u32,
    who: String,
    to: String,
    asset_ids: Vec<u64>,
    asset_amounts: Vec<u128>,
    currency_amounts: Vec<u128>,
}

/// Add liquidity to dex
pub async fn add_liquidity(
    data: web::Data<AppState>,
    req: web::Json<AddLiquidityInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.to).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                    .tx()
                    .dex()
                    .add_liquidity(
                        req.exchange_id,
                        to,
                        req.asset_ids.clone(),
                        req.asset_amounts.clone(),
                        req.max_currencies.clone(),
                    )
                    .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::dex::events::LiquidityAdded>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(AddLiquidityOutput {
                        exchange_id: event.exchange_id,
                        who: event.who.to_string(),
                        to: event.to.to_string(),
                        asset_ids: event.asset_ids,
                        asset_amounts: event.asset_amounts,
                        currency_amounts: event.currency_amounts,
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::dex::events::CurrencyToAsset"),
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
pub struct RemoveLiquidityInput {
    to: String,
    exchange_id: u32,
    asset_ids: Vec<u64>,
    liquidities: Vec<u128>,
    min_currencies: Vec<u128>,
    min_assets: Vec<u128>,
}

#[derive(Serialize, Deserialize)]
pub struct RemoveLiquidityOutput {
    exchange_id: u32,
    who: String,
    to: String,
    asset_ids: Vec<u64>,
    asset_amounts: Vec<u128>,
    currency_amounts: Vec<u128>,
}

/// Remove liquidity from dex
pub async fn remove_liquidity(
    data: web::Data<AppState>,
    req: web::Json<RemoveLiquidityInput>,
    claims: KeycloakClaims<user::ClaimsWithEmail>
) -> error::Result<HttpResponse> {
    match user::get_seed(&claims.sub).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                let user_seed = response.seed.clone().unwrap();

                let pair = get_pair_from_seed(&user_seed)?;
                let signer = PairSigner::new(pair);
                let to = sp_core::sr25519::Public::from_str(&req.to).map_err(map_account_err)?;
                let to = sp_core::crypto::AccountId32::from(to);
                let api = data.api.lock().unwrap();
                let result = api
                    .tx()
                    .dex()
                    .remove_liquidity(
                        req.exchange_id,
                        to,
                        req.asset_ids.clone(),
                        req.liquidities.clone(),
                        req.min_currencies.clone(),
                        req.min_assets.clone(),
                    )
                    .sign_and_submit_then_watch(&signer)
                    .await
                    .map_err(map_subxt_err)?
                    .wait_for_finalized_success()
                    .await
                    .map_err(map_subxt_err)?;
                let result = result
                    .find_first_event::<sugarfunge::dex::events::LiquidityRemoved>()
                    .map_err(map_subxt_err)?;
                match result {
                    Some(event) => Ok(HttpResponse::Ok().json(RemoveLiquidityOutput {
                        exchange_id: event.exchange_id,
                        who: event.who.to_string(),
                        to: event.to.to_string(),
                        asset_ids: event.asset_ids,
                        asset_amounts: event.asset_amounts,
                        currency_amounts: event.currency_amounts,
                    })),
                    None => Ok(HttpResponse::BadRequest().json(RequestError {
                        message: json!("Failed to find sugarfunge::dex::events::CurrencyToAsset"),
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
