// Converts cookies.sqlite to cookies.txt
use std::path::Path;
use std::fs::File;
use std::io::{Write, Read};
use sqlite::open;
use lz4::block::decompress;
use json::{parse, JsonValue};
use regex::Regex;
use std::collections::HashMap;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
enum Browser {
    Firefox,
    Chrome
}

fn decrypt_chrome_cookie_value(encrypted_value: &str) -> String {
    unimplemented!();
}

struct Cookie {
    domain: String,
    flag: String,
    path: String,
    secure: String,
    expiration: String,
    name: String,
    value: String
}

impl Cookie {
    fn from_sqlite_db(sqlite_file: &Path, domain_substring_filter: Option<&str>, browser: Browser) -> Vec<Cookie> {
        let connection = open(sqlite_file).unwrap();
        let query = match browser {
            Browser::Firefox => {
                if let Some(domain_substring_filter) = domain_substring_filter {
                    format!("SELECT * FROM moz_cookies WHERE host LIKE '%{}%'", domain_substring_filter)
                } else {
                    String::from("SELECT * FROM moz_cookies")
                }
            },
            Browser::Chrome => {
                if let Some(domain_substring_filter) = domain_substring_filter {
                    format!("SELECT * FROM cookies WHERE host LIKE '%{}%'", domain_substring_filter)
                } else {
                    String::from("SELECT * FROM cookies")
                }
            },
        };

        let mut cookies = Vec::new();
        match browser {
            Browser::Firefox => {
                connection.iterate(query, |row| {
                    let row: HashMap<&str, Option<&str>> = row.iter().cloned().collect();
                    let domain = row.get("host").expect("Error: domain not found in Mozilla cookie.").unwrap().to_string();
                    let flag = if domain.starts_with('.') { "TRUE".to_string() } else { "FALSE".to_string() }; 
                    let path = row.get("path").expect("Error: path not found in Mozilla cookie.").unwrap().to_string();
                    let secure = if row.get("isSecure").expect("Error: isSecure not found in Mozilla cookie.").unwrap() == "0" {"FALSE".to_string()} else {"TRUE".to_string()};
                    let expiration = row.get("expiry").expect("Error: expiry not found in Mozilla cookie.").unwrap().to_string();
                    let name = row.get("name").expect("Error: name not found in Mozilla cookie.").unwrap().to_string();
                    let value = row.get("value").expect("Error: value not found in Mozilla cookie.").unwrap().to_string();
                    cookies.push(Cookie{domain,flag,path,secure,expiration,name,value});
                    true
                }).unwrap();
            },
            Browser::Chrome => {
                // Chrome has some cookie data that's not UTF8, so connection.iterate() will panic
                let mut rows = connection.prepare(query).unwrap();
                while let Ok(sqlite::State::Row) = rows.next() { 
                    let mut row: HashMap<&str, Option<String>> = (0..rows.column_count()).into_iter().map(|i| (rows.column_name(i), rows.read(i).ok())).collect();
                    let domain = row.remove("host_key").expect("Error: domain not found in Chrome cookie.").unwrap();
                    let flag = if domain.starts_with('.') { "TRUE".to_string() } else { "FALSE".to_string() }; 
                    let path = row.remove("path").expect("Error: path not found in Chrome cookie.").unwrap();
                    let secure = if row.remove("is_secure").expect("Error: secure not found in Chrome cookie.").unwrap() == "0" {"FALSE".to_string()} else {"TRUE".to_string()};
                    let expiration = row.remove("expires_utc").expect("Error: expiry not found in Chrome cookie.").unwrap();
                    let name = row.remove("name").expect("Error: name not found in Chrome cookie.").unwrap();
                    let value = if row.get("value").unwrap().is_some() && row.get("value").unwrap().as_ref().unwrap() != "" {
                        row.remove("value").unwrap().unwrap()
                    } else {
                        let encrypted_value = row.remove("encrypted_value").expect("Error: encrypted_value not found in Chrome cookie.").unwrap();
                        decrypt_chrome_cookie_value(&encrypted_value)
                    };
                    cookies.push(Cookie{domain,flag,path,secure,expiration,name,value});
                }
                // For some reason, rows.next() == Ok(Row) at this point...
            }
        };
        cookies
    }

    // Session cookies may appear in this format
    fn from_lz4_file(lz4_path: &Path, domain_substring_filter: Option<&str>, browser: Browser) -> Vec<Cookie> {
        let mut lz4_file = File::open(lz4_path).unwrap();
        let mut buffer = Vec::new();
        let mut cookies = Vec::new();
        match browser {
            Browser::Firefox => {
                let header_length = 8; // Mozilla-specific? 
                lz4_file.read_to_end(&mut buffer).unwrap();
                buffer = decompress(&buffer[header_length..], None).unwrap();
                let json = parse(std::str::from_utf8(&buffer).unwrap()).expect("Error parsing json");
                if let JsonValue::Object(object) = json {
                    let cookie_array = object.get("cookies").unwrap();
                    // CLEAN THIS UP
                    for json_cookie in cookie_array.members().filter_map(|val| { 
                        if let JsonValue::Object(json_cookie) = val { // Must be object
                            if let Some(domain) = json_cookie.get("host") { // Must have a domain field
                                if let Some(domain_substring_filter) = domain_substring_filter { // Must match domain filter if present
                                    if Regex::new(&format!("\\w*{}\\w*", domain_substring_filter)).unwrap().is_match(domain.as_str().unwrap()) {
                                        Some(json_cookie)
                                    } else {
                                        None
                                    }
                                } else { 
                                    Some(json_cookie)
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }) {        
                        let domain = json_cookie.get("host").expect("Error: domain not found in Mozilla session cookie.").as_str().unwrap().to_string();
                        let flag = if domain.starts_with('.') { "TRUE".to_string() } else { "FALSE".to_string() }; 
                        let path = json_cookie.get("path").expect("Error: path not found in Mozilla session cookie.").as_str().unwrap().to_string();
                        let secure = if json_cookie.get("secure").unwrap_or(&JsonValue::Boolean(true)).as_bool().unwrap() {"TRUE".to_string()} else {"FALSE".to_string()}; // Make sure that true is the reasonable default. 
                        let expiration = String::from("0"); // Session cookie
                        let name = json_cookie.get("name").expect("Error: name not found in Mozilla session cookie.").as_str().unwrap().to_string();
                        let value = json_cookie.get("value").expect("Error: value not found in Mozilla session cookie.").as_str().unwrap().to_string();
                        cookies.push(Cookie{domain,flag,path,secure,expiration,name,value});
                    }
                }
            },
            Browser::Chrome => {
                // It might be that Chrome session cookies are stored in the sqlite file
                unimplemented!();
            }
        };
        cookies
    }

    fn netscape_cookie_file_format(cookies: &[Cookie]) -> String {
        let mut serialized_cookies = String::from("# Netscape HTTP Cookie File\n\n");
        for cookie in cookies {
            serialized_cookies.push_str(&cookie.serialize_netscape_format());
            serialized_cookies.push('\n');
        }
        serialized_cookies
    }

    fn serialize_netscape_format(&self) -> String {
        format!("{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.domain,
            self.flag,
            self.path,
            self.secure,
            self.expiration,
            self.name,
            self.value   
        )
    }
}

pub fn firefox_cookies(profile_folder: &Path, domain_substring_filter: Option<&str>) -> String {
    let other_cookies_path = profile_folder.join("cookies.sqlite");
    let session_cookies_path = profile_folder.join("sessionstore-backups/recovery.baklz4"); 
    let mut cookies = Cookie::from_sqlite_db(&other_cookies_path, domain_substring_filter, Browser::Firefox);
    cookies.append(&mut Cookie::from_lz4_file(&session_cookies_path, domain_substring_filter, Browser::Firefox));
    Cookie::netscape_cookie_file_format(&cookies)
}

pub fn firefox_cookie_file(profile_folder: &Path, domain_substring_filter: Option<&str>, out_path: &Path) {
    let mut out_file = File::create(out_path).unwrap();
    let cookie_file_content = firefox_cookies(profile_folder, domain_substring_filter);
    out_file.write_all(cookie_file_content.as_bytes()).unwrap();
}

pub fn chrome_cookies(profile_folder: &Path, domain_substring_filter: Option<&str>) -> String {
    unimplemented!("");
    // let other_cookies_path = profile_folder.join("Network/Cookies");
    // // let session_cookies_path = profile_folder.join("...");
    // let cookies = Cookie::from_sqlite_db(&other_cookies_path, domain_substring_filter, Browser::Chrome);
    // // cookies.append(&mut Cookie::from_lz4_file(&session_cookies_path, domain_substring_filter, Browser::Chrome));
    // Cookie::netscape_cookie_file_format(&cookies)
}

pub fn chrome_cookie_file(profile_folder: &Path, domain_substring_filter: Option<&str>, out_path: &Path) {
    let mut out_file = File::create(out_path).unwrap();
    let cookie_file_content = chrome_cookies(profile_folder, domain_substring_filter);
    out_file.write_all(cookie_file_content.as_bytes()).unwrap();
}