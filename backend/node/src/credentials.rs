use crate::db::NodeDbContext;

use mvp::{
    messages::{
        users::{
            NewUserResponse,
            NewUserResult,
            NewUserSession,
            UserAuthResponse,
            UserAuthSession,
        },
        ResponseErrorWrapper,
    },
    random::get_secure_random_bytes,
};

use anyhow::Result;
use chrono::{ DateTime, Utc };
use serde::{ Deserialize, Serialize };
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct User {
    pub user_id: Uuid,
    pub email: String,
    pub password: String,
    pub fade_date: Option<DateTime<Utc>>,
}

// *** HANDLERS *** //

//handler that is called from node bin to create a new user
pub fn handle_new_user_credentials(
    connection: nats::Connection,
    db_context: &mut NodeDbContext,
    message: nats::Message
) -> Result<(), anyhow::Error> {
    let session = serde_json::from_slice::<NewUserSession>(&message.data);
    store_new_user_creds(connection, db_context, session.unwrap())
}

// handler that is called from node bin. checks credentials when a user tries to log in
pub fn handle_user_auth_credentials(
    connection: nats::Connection,
    db_context: &mut NodeDbContext,
    message: nats::Message
) -> Result<(), anyhow::Error> {
    let session = serde_json::from_slice::<UserAuthSession>(&message.data);
    auth_user_creds(connection, db_context, session.unwrap())
}

fn auth_user_creds(
    connection: nats::Connection,
    db_context: &mut NodeDbContext,
    message: UserAuthSession
) -> Result<(), anyhow::Error> {
    let mut auth_response = UserAuthResponse {
        response: None,
        error_response: None,
    };
    let subject = format!("network.gridlock.nodes.User.Auth.{}.result", &message.session);
    let mut user: User = match get_user(db_context, &message.email) {
        Ok(option) =>
            match option.into_iter().next() {
                Some(value) => value,
                None => {
                    send_result(connection, auth_response, &subject)?;
                    return Ok(());
                }
            }
        Err(e) => {
            auth_response.error_response = Option::from(e);
            send_result(connection, auth_response, &message.session)?;
            return Ok(());
        }
    };

    // check if the user is trying to login with a password otherwise check for a fade date
    if let Some(password) = message.password {
        if argon2::verify_encoded(&user.password, password.as_bytes())? {
            auth_response.response = Option::from(user.user_id);
            send_result(connection, auth_response, &subject)?;

            // Cancel security fadeout after a successful login
            if user.fade_date.is_some() {
                user.fade_date = None;
                update_user_fade_date(db_context, user);
            }
        } else {
            send_result(connection, auth_response, &subject)?;
        }
    } else {
        // Check if there is a fade date set
        if let Some(value) = user.fade_date {
            // if fade date passes the user can access without a password
            let days_left = time_left_from_date_to_now(value);
            // if the fade date has passed the user gains access
            if days_left < chrono::Duration::zero() {
                // user id to return
                // clear fade date now that it has passed
                user.fade_date = None;
                match update_user_fade_date(db_context, user.clone()) {
                    Ok(_value) => {
                        auth_response.response = Option::from(user.user_id);
                        send_result(connection, auth_response, &subject)?;
                    }
                    Err(e) => {
                        auth_response.error_response = Option::from(e);
                        send_result(connection, auth_response, &subject)?;
                    }
                };
            }
        } else {
            // return 0 if no fade was set
            send_result(connection, auth_response, &subject)?;
        }
    }

    Ok(())
}

fn time_left_from_date_to_now(date: DateTime<Utc>) -> chrono::Duration {
    let current_date: DateTime<Utc> = Utc::now();
    date.signed_duration_since(current_date)
}

// creates user and returns  response to comm hub
fn store_new_user_creds(
    connection: nats::Connection,
    db_context: &mut NodeDbContext,
    message: NewUserSession
) -> Result<(), anyhow::Error> {
    //create response subject for comm hub
    let subject = format!("network.gridlock.nodes.User.storing.{}.result", &message.session);

    let mut new_user_response = NewUserResponse {
        response: NewUserResult::CreateUserError,
        error_response: None,
    };

    //check if User already exists
    let user = match get_user(db_context, &message.email) {
        Ok(value) => value,
        Err(e) => {
            new_user_response.error_response = Option::from(e);
            send_result(connection, new_user_response, &message.session)?;
            return Ok(());
        }
    };

    if let Some(_user) = user.into_iter().next() {
        new_user_response.response = NewUserResult::EmailConflict;
        send_result(connection, new_user_response, &subject)?;
    } else {
        // Hash the password
        let hashed_password = argon2::hash_encoded(
            message.password.as_bytes(),
            &get_secure_random_bytes(16), // random salt, 16 random bytes recommended by Argon2 Wikipedia article
            &argon2::Config::default()
        )?;

        // content to be stored
        let user_file_content = User {
            user_id: message.user_id,
            email: message.email,
            password: hashed_password,
            fade_date: None,
        };

        match create_user(db_context, &user_file_content) {
            Ok(_last_row) => {
                new_user_response.response = NewUserResult::Success;
                send_result(connection, new_user_response, &subject)?;
            }
            Err(e) => {
                new_user_response.error_response = Option::from(e);
                send_result(connection, new_user_response, &subject)?;
            }
        }
    }

    Ok(())
}

// creates user on DB
fn create_user(db_context: &mut NodeDbContext, user: &User) -> Result<i64, ResponseErrorWrapper> {
    NodeDbContext::create_user(db_context, user).map_err(|e| ResponseErrorWrapper::from(e))
}
// gets user on DB
fn get_user(
    db_context: &mut NodeDbContext,
    email: &str
) -> Result<Vec<User>, ResponseErrorWrapper> {
    NodeDbContext::get_user_by_email(db_context, email).map_err(|e| ResponseErrorWrapper::from(e))
}

// updates fading security date on DB
fn update_user_fade_date(
    db_context: &mut NodeDbContext,
    user: User
) -> Result<usize, ResponseErrorWrapper> {
    NodeDbContext::update_user_fade_date(db_context, user).map_err(|e|
        ResponseErrorWrapper::from(e)
    )
}

// *** GENERIC FUNCTIONS *** //

fn send_result<T: Serialize>(
    connection: nats::Connection,
    msg: T,
    subject: &str
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(&msg)?;
    connection.publish(subject, &json)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use rusqlite::Connection as SqliteConnection;

    const TEST_EMAIL: &str = "example@example.com";
    const TEST_PASSWORD: &str = "test-password";

    fn init_db() -> SqliteConnection {
        use crate::db::create_table_users;

        let db_conn = SqliteConnection::open_in_memory().unwrap();
        create_table_users(&db_conn);

        return db_conn;
    }

    #[test]
    fn test_create_and_retrieve_user() {
        let db = init_db();
        let mut context = NodeDbContext::new(&db);

        let new_user = User {
            user_id: Uuid::new_v4(),
            email: String::from(TEST_EMAIL),
            password: String::from(TEST_PASSWORD),
            fade_date: None,
        };

        let create_user_result = create_user(&mut context, &new_user);
        assert!(create_user_result.is_ok());
        assert_eq!(create_user_result.unwrap(), 1);

        let get_user_result = get_user(&mut context, TEST_EMAIL);
        assert!(get_user_result.is_ok());

        let get_user_result = get_user_result.unwrap();
        assert_eq!(get_user_result.len(), 1);
        assert_eq!(get_user_result[0], new_user);
    }

    #[test]
    fn test_retrieve_nonexistent_user() {
        let db = init_db();
        let mut context = NodeDbContext::new(&db);

        let get_user_result = get_user(&mut context, TEST_EMAIL);
        assert!(get_user_result.is_ok());
        assert_eq!(get_user_result.unwrap().len(), 0);
    }
}
