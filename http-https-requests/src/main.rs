extern crate reqwest;

fn main() {

 let client = reqwest::blocking::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
 let _response = client.post("https://google.com/test").header("Authorization", "testtest" ).body("test").send();
 let test = _response.unwrap().text().unwrap();
 let client2 = reqwest::blocking::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
 let url = "https://google.com";
 let argumentsdata = format!("register={}","1234");
 let concat = [url,&argumentsdata].join("/");
 client2.get(&concat).send();

}
