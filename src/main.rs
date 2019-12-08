use clap;
use fastping_rs;
use std::net::IpAddr;
use std::ops::Deref;
use std::collections::HashMap;
use serde_json;
use regex::Regex;
use std::io::{BufReader, BufRead};

struct Entry {
    ip: IpAddr,
    mac: String,
}

fn main() {
//    check_platform_compatibility();

    let matches =
        clap::App::new("Who Is Home")
            .version("0.1")
            .author("steve")
            .about("Find out who is on your network")
            .arg(clap::Arg::with_name("id_file_path")
                .short("-f")
                .long("--id-file")
                .value_name("ID FILE")
                .help("Path to a file that contains the ids")
                .long_help("Path to an .ini file where the key is a mac address and the value is a custom identifier. Example: 11:22:33:44:55:66=Steve Shani")
                .takes_value(true)
            )
            .arg(clap::Arg::with_name("interface")
                .short("i")
                .long("interface")
                .value_name("INTERFACE")
                .help("The interface that the ARP packets came from")
                .takes_value(true)
            )
            .arg(clap::Arg::with_name("mask")
                .short("m")
                .long("mask")
                .value_name("IP MASK")
                .help("Filter IP Addresses")
                .long_help("A regex that will be matched against IP addresses found in the ARP cache")
                .takes_value(true)
            )
            .arg(clap::Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .value_name("verbose")
                .takes_value(false)
            )
            .get_matches();

    let mut mask = String::from(".*");

    if matches.is_present("mask") {
        mask = String::from(matches.value_of("mask").unwrap());
    }

    let addresses = vec![];// = get_addresses_from_arp_table(mask, matches.is_present("verbose"));
//    let addresses = get_connected_addresses(addresses, matches.is_present("verbose"));
    print_connected_addresses(addresses, matches.value_of("id_file_path"))
}


fn print_connected_addresses(addresses: Vec<Entry>, id_file: Option<&str>) {
    let mut map = std::collections::HashMap::new();
    if id_file.is_some() {
        let file = std::fs::File::open(id_file.unwrap()).expect("Unable to open identifiers file");
        let mut file = BufReader::new(&file);
        for line in file.lines() {
            let line = line.unwrap();
            let (mac, name) = line.split_at(line.find("=").unwrap());
            map.insert(String::from(mac), String::from(name));
        }
    }

    println!("Connected Clients:");

    for address in addresses {
        let ip_address = address.ip.to_string();
        let id = match map.get(&address.mac) {
            Some(name) => name,
            _ => &ip_address
        };

        println!("{}", *id);
    }
}

fn get_addresses_from_arp_table(regex: String, verbose: bool) -> Vec<Entry> {
    let regex = Regex::new(regex.as_str()).expect("Unable to parse regex");
    let output = std::process::Command::new("/usr/sbin/arp")
        .args(&["-a", "--libxo", "json"])
        .output()
        .expect("Failed To Run ARP");
    let arp_info = String::from_utf8(output.stdout).unwrap_or(String::from("{}"));
    let arp_info: serde_json::Value = serde_json::from_str(arp_info.as_str()).expect("Unable to read ARP output");
    let mut ip_addresses: Vec<Entry> = vec![];
    arp_info["arp"]["arp-cache"].as_array().expect("unable to parse ARP output").into_iter().for_each(|entry| {
        let ip_address = entry["ip-address"].as_str().expect("Unable to parse ARP IP Addresses");
        let mac_address = String::from(entry["mac-address"].as_str().expect("Unable to parse MAC"));
        if !regex.is_match(ip_address) {
            if verbose {
                println!("Skipping {}", ip_address);
            }
            return;
        }
        let ip_address = match ip_address.parse::<IpAddr>() {
            Ok(address) => address,
            Err(e) => panic!("Unable to parse IP Address")
        };
        ip_addresses.push(Entry { ip: ip_address, mac: mac_address });
        if verbose {
            println!("Added {} to scan", ip_address);
        }
    });

    return ip_addresses;
}


fn get_connected_addresses(mut arp_addresses: Vec<Entry>, verbose: bool) -> Vec<Entry> {
    let total_arp_addresses = arp_addresses.len();
    let (mut pinger, results) = match fastping_rs::Pinger::new(None, None) {
        Ok((pinger, results)) => (pinger, results),
        Err(e) => panic!("Error: {}", e)
    };


    arp_addresses.iter().for_each(|address| {
        pinger.add_ipaddr((address.deref().ip).to_string().as_str());
    });

    let mut address_confirmations: HashMap<IpAddr, u8> = std::collections::HashMap::new();
    let mut finished_addresses: usize = 0;

    println!("Starting Scan");

    pinger.run_pinger();

    while finished_addresses != total_arp_addresses {
        match results.recv().unwrap() {
            fastping_rs::PingResult::Idle { addr } => {
                let number_of_tries = match address_confirmations.get_mut(&addr) {
                    Some(address) => address,
                    _ => {
                        address_confirmations.insert(addr, 1);
                        address_confirmations.get_mut(&addr).unwrap()
                    }
                };

                if verbose {
                    println!("Unreachable Address {}. Attempt {}", addr, *number_of_tries);
                }

                if *number_of_tries == 2 {
                    pinger.remove_ipaddr(addr.to_string().as_str());
                    arp_addresses.remove(arp_addresses.iter().position(|x| (*x).ip == addr).unwrap());
                    finished_addresses += 1;
                } else {
                    *number_of_tries += 1;
                }
            }

            fastping_rs::PingResult::Receive { addr, rtt } => {
                if verbose {
                    println!("Receive from Address {} in {:?}.", addr, rtt);
                }
                pinger.remove_ipaddr(addr.to_string().as_str());
                finished_addresses += 1;
            }
        }
    }

    pinger.stop_pinger();

    return arp_addresses;
}


fn check_platform_compatibility() -> bool {
    if !cfg!(freebsd) {
        eprintln!("This platform is not supported at this time");
        std::process::exit(1);
    }

    return true;
}
