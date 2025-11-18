# stun

## Run

```
use stun::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_hostname("stun.l.google.com:19302")?;
    let public_addr = client.get_public_address()?;
    println!("Your public address: {}", public_addr);

    Ok(())
}
```

## License

This project is licensed under the ISC license ([LICENSE](LICENSE) or http://opensource.org/licenses/ISC)
