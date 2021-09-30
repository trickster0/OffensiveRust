use wmi::{COMLibrary, WMIConnection};
use std::collections::HashMap;


fn main() -> Result<(), Box<dyn std::error::Error>>  {
    let _initialized_com = COMLibrary::new()?;

    let wmi_con = unsafe { WMIConnection::with_initialized_com(Some("ROOT\\securitycenter2"))? };
    let results: Vec<HashMap<String, String>> = wmi_con.raw_query("SELECT displayName FROM AntiVirusProduct").unwrap();
    for av in results {
        println!("{:?}",av.get("displayName").unwrap());
    }
    
    Ok(())
}
