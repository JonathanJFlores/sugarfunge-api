use crate::account;
use crate::config::Config;
use serde::{Deserialize, Serialize};
use actix_web::{
    web,
    Responder,
    HttpRequest,
    body,
    http::{header, StatusCode}
};
use serde_json::json;
use awc::{self};
use actix_web_middleware_keycloak_auth::{KeycloakClaims};

#[derive(Serialize, Deserialize, Debug)]
struct Credentials {
    grant_type: String,
    client_id: String,
    username: String,
    password: String,
    client_secret: String,
    scope: String
}

#[derive(Serialize, Deserialize)]
pub struct SugarTokenOutput {
    pub access_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorMessageOutput {
    error: String,
    message: String
}

pub async fn get_sugarfunge_token(env: web::Data<Config>) -> Result<SugarTokenOutput, impl Responder> {
    let config = &env;
    let endpoint = config.keycloak_host.to_string() + "/auth/realms/" + &config.keycloak_realm + "/protocol/openid-connect/token";

    let credentials = web::Data::new(Credentials{
        client_id: config.keycloak_client_id.to_string(),
        grant_type: "password".to_string(),
        username: config.keycloak_username.to_owned(),
        password: config.keycloak_user_password.to_owned(),
        client_secret: config.keycloak_client_secret.to_owned(),
        scope: "openid".to_string()
    });

    let awc_client = awc::Client::new();

    let response = awc_client.post(endpoint)
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .send_form(&credentials)
        .await; 

    match response {
        Ok(mut response) => {
            match response.status() {
                StatusCode::OK => {
                    let body_str: String = std::str::from_utf8(&response.body().await.unwrap()).unwrap().to_string();
                    let body: SugarTokenOutput = serde_json::from_str(&body_str).unwrap();
                    Ok(body)
                },
                _ => {
                    Err(web::Json(
                        ErrorMessageOutput {
                            error: "Error request".to_string(),
                            message: "Error when requesting token".to_string()
                        }
                    ))
                }
            }
        },
        Err(_) => Err(web::Json(
            ErrorMessageOutput {
                error: "Unknown".to_string(),
                message: "Error Unknown".to_string()
            }
        ))
    }
}


#[derive(Debug,Serialize, Deserialize)]
pub struct UserInfo {
    id: String,
    attributes: Option<UserAtributes>,
    email: String,
    #[serde(rename = "emailVerified", default)]
    email_verified: bool,
    username: String,
    #[serde(rename = "firstName", default)]
    first_name: String,
    #[serde(rename = "lastName", default)]
    last_name: String,
}

#[derive(Debug,Serialize, Deserialize, Default, Clone)]
pub struct UserAtributes {
    #[serde(rename = "user-seed", default)]
    user_seed: Box<[String]>
}


#[derive(Debug, Serialize, Deserialize)]
pub struct UserSeedOutput {
    pub seed: Option<String>
}


pub async fn get_seed(
    user_id: &String,
    env: web::Data<Config>
) -> Result<web::Json<UserSeedOutput>, web::Json<UserSeedOutput>> { 
    let config = env.clone();

    match get_sugarfunge_token(env).await {
        Ok(response) => {
            // println!("{:?}", response.access_token);
            let awc_client = awc::Client::new();
            let endpoint = format!("{}/auth/admin/realms/{}/users/{}", config.keycloak_host, config.keycloak_realm, user_id); 

            let user_response = awc_client.get(endpoint)
                .append_header((header::ACCEPT, "application/json"), )
                .append_header((header::CONTENT_TYPE, "application/json"))
                .append_header((header::AUTHORIZATION, "Bearer ".to_string() + &response.access_token))
                .send()
                .await; 

            match user_response {
                Ok(mut user_response) => {
                    
                    match user_response.status() {
                        StatusCode::OK => {
                            let body_str: String = std::str::from_utf8(&user_response.body().await.unwrap()).unwrap().to_string();
                            let user_info: UserInfo = serde_json::from_str(&body_str).unwrap();

                            // println!("{:?}", &user_info);
                            if !user_info.attributes.clone().unwrap_or_default().user_seed.is_empty() {
                                let user_seed = user_info.attributes.clone().unwrap_or_default().user_seed[0].clone();
                                Ok(web::Json(
                                    UserSeedOutput {
                                        seed: Some(user_seed)
                                    }
                                ))
                            } else {
                                Ok(web::Json(
                                    UserSeedOutput {
                                        seed: Some("".to_string())
                                    }
                                ))
                            }
                        },
                        _ => Err(web::Json(
                            UserSeedOutput {
                                seed: None
                            }
                        ))
                    }
                }
                Err(_) => Err(web::Json(
                        UserSeedOutput {
                            seed: None
                        }
                    ))
                }


        }
        Err(_e) => Err(web::Json(
            UserSeedOutput {
                seed: None
            }
        ))
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct InsertUserSeedOutput {
    error: Option<String>,
    message: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAccountOutput {
    seed: String,
    account: String,
}

pub async fn insert_seed_user(
    user_id: &String,
    req: HttpRequest,
    env: web::Data<Config>
) -> Result<web::Json<InsertUserSeedOutput>, web::Json<InsertUserSeedOutput>> { 
    let config = env.clone();

    match get_sugarfunge_token(env).await {
        Ok(response) => {
            match account::create(req).await {
                Ok(response_account) => {                    
                    
                    let bytes = body::to_bytes(response_account.into_body()).await.unwrap();
                    let str_bytes = std::str::from_utf8(&bytes).unwrap().to_string();
                    let body: CreateAccountOutput = serde_json::from_str(&str_bytes).unwrap();
                    // println!("CreateAccountOutput {:?}", body);
                    
                    let awc_client = awc::Client::new();
                    let endpoint = format!("{}/auth/admin/realms/{}/users/{}", config.keycloak_host, config.keycloak_realm, user_id); 

                    let attributes = json!({
                        "attributes": {
                            "user-seed": [
                                body.seed
                            ]
                        }
                    });
        
                    let response = awc_client.put(endpoint)
                        .append_header((header::ACCEPT, "application/json"), )
                        .append_header((header::CONTENT_TYPE, "application/json"))
                        .append_header((header::AUTHORIZATION, "Bearer ".to_string() + &response.access_token))
                        .send_json(&attributes)
                        .await;
        
                    match response {
                        Ok(response) => {
                            match response.status() { 
                                StatusCode::NO_CONTENT => {
                                    Ok(web::Json(
                                        InsertUserSeedOutput {
                                            error: None,
                                            message: "Attribute insert to user attributes".to_string()
                                        }
                                    ))
                                }
                                _ => {
                                    Err(web::Json(
                                        InsertUserSeedOutput {
                                        error: Some("Error Insert Attribute".to_string()),
                                        message: "Error when insert attribute to user".to_string()
                                    }
                                  ))
                                }
                            }
                        }
                        Err(_e) => {
                            Err(web::Json(
                                InsertUserSeedOutput {
                                    error: Some("Error Insert Attribute".to_string()),
                                    message: "Unknown Error".to_string()
                                }
                          ))
                        }
                    }
                }
                Err(_) => {
                    Err(web::Json(
                        InsertUserSeedOutput {
                            error: Some("Error Insert Attribute".to_string()),
                            message: "Unknown Error".to_string()
                        }
                    ))
                }
            }            

        }
        Err(_error) => {
            Err(web::Json(
                InsertUserSeedOutput {
                    error: Some("Error Insert Attribute".to_string()),
                    message: "Unknown Error".to_string()
                }
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ClaimsWithEmail {
    pub sub: String,
    name: String,
    preferred_username: String,
    given_name: String,
    family_name: String,
    email: String
}

pub async fn verify_seed(
    claims: KeycloakClaims<ClaimsWithEmail>,
    req: HttpRequest,
    env: web::Data<Config>
) ->  impl Responder { 

    match get_seed(&claims.sub, env.clone()).await {
        Ok(response) => {
            if !response.seed.clone().unwrap_or_default().is_empty() {
                web::Json(
                    InsertUserSeedOutput {
                        error: None,
                        message: "User with atrribute".to_string()
                    }
                )
            } else {
                match insert_seed_user(&claims.sub, req, env).await {
                    Ok(response) => { response }
                    Err(error) => {error}
                }
            }
        },
        Err(_) => {
            web::Json(
                InsertUserSeedOutput {
                    error: Some("Unknown Error".to_string()),
                    message: "Unknown Error".to_string()
                }
            )
        }
    }
}