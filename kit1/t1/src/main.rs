use std::fs;
use std::io::{self, Write};
use std::collections::HashMap;

fn main() -> io::Result<()> {
    // Prompt the user for a file name
    print!("Enter the file name: ");
    io::stdout().flush()?; // Ensure the prompt is printed immediately

    let mut file_name = String::new();
    io::stdin().read_line(&mut file_name)?;
    let file_name = file_name.trim();

    // Read the file contents as bytes
    let data = fs::read(file_name).expect("Failed to read the file");

    // Check the number of bytes
    let num_bytes = data.len();

    // Verify that it is 32 bytes long, warn if not
    if num_bytes != 32 {
        eprintln!("Warning: File has {} bytes, expected 32 bytes for an encryption key.", num_bytes);
    }

    // Count frequency for each byte using a HashMap
    let mut frequency = HashMap::new();
    for &byte in &data {
        *frequency.entry(byte).or_insert(0) += 1;
    }
    // Count the number of repeating groups: each byte with frequency > 1
    let repeating_groups = frequency.values().filter(|&&count| count > 1).count();

    // Determine if all bytes are unique
    let all_unique = repeating_groups == 0;

    // Generate HTML content
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("  <meta charset=\"UTF-8\">\n");
    html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("  <title>File Data Analysis</title>\n");
    html.push_str("  <style>\n");
    html.push_str("    table { border-collapse: collapse; width: 100%; }\n");
    html.push_str("    th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }\n");
    html.push_str("    th { background-color: #f2f2f2; }\n");
    html.push_str("  </style>\n");
    html.push_str("</head>\n<body>\n");
    html.push_str(&format!("<h1>Analysis of File: {}</h1>\n", file_name));
    html.push_str(&format!("<p>Total bytes: {}</p>\n", num_bytes));
    html.push_str(&format!("<p>All bytes unique? {}</p>\n", if all_unique { "Yes" } else { "No" }));
    if !all_unique {
        html.push_str(&format!("<p>Number of repeating groups: {}</p>\n", repeating_groups));
    }

    // Build the table header
    html.push_str("<table>\n<thead>\n<tr>\n");
    html.push_str("  <th>Index</th>\n");
    html.push_str("  <th>Hex</th>\n");
    html.push_str("  <th>Binary</th>\n");
    html.push_str("  <th>ASCII</th>\n");
    html.push_str("</tr>\n</thead>\n<tbody>\n");

    // Build a row for each byte
    for (i, &byte) in data.iter().enumerate() {
        let hex_str = format!("{:02X}", byte);
        let bin_str = format!("{:08b}", byte);
        // For the ASCII representation, show the character if printable; otherwise show a dot.
        let ascii_char = if byte.is_ascii_graphic() || byte == b' ' {
            byte as char
        } else {
            '.'
        };

        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            i, hex_str, bin_str, ascii_char
        ));
    }

    html.push_str("</tbody>\n</table>\n");
    html.push_str("</body>\n</html>");

    // Write the HTML to a file named "data.html"
    fs::write("data.html", html)?;
    println!("HTML report generated as data.html");

    Ok(())
}

