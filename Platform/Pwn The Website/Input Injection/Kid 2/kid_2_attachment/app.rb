require 'sinatra'
require 'jwt'
require 'openssl'
require 'base64'


set :bind, '0.0.0.0'
set :port, 80
set :views, File.join(File.dirname(__FILE__), 'views')

# Generate RSA Key Pair on startup
rsa_key = OpenSSL::PKey::RSA.new(2048)
PUBLIC_KEY_FILE = 'public_key.pem'
File.write(PUBLIC_KEY_FILE, rsa_key.public_key.to_pem)

helpers do
  def h(text)
    Rack::Utils.escape_html(text)
  end
end

get '/' do
  redirect '/login'
end

get '/login' do
  erb :index
end

post '/login' do
  username = params[:username]
  password = params[:password]
  
  target_user = ENV['PWN'] || 'testuser'
  
  if username == target_user && password == 'anyaunyu'
    payload = {
      username: username,
      role: 'user',
      exp: Time.now.to_i + 3600
    }
    
    headers = {
      kid: PUBLIC_KEY_FILE
    }
    
    token = JWT.encode(payload, rsa_key, 'RS256', headers)
    
    response.set_cookie(:token, value: token, path: '/', httponly: true)
    redirect '/dashboard'
  else
    @error = "Invalid credentials"
    erb :index
  end
end

get '/dashboard' do
  token = request.cookies['token']
  
  if token.nil? || token.empty?
    redirect '/login'
    return
  end
  
  begin
    decoded_token = JWT.decode(token, nil, false)
    header = decoded_token[1]
    kid = header['kid']
    
    public_key_content = open(kid).read
    public_key = OpenSSL::PKey::RSA.new(public_key_content)
    
    decoded = JWT.decode(token, public_key, true, { algorithm: 'RS256' })
    @claims = decoded[0]
    
    if @claims['role'] == 'admin'
    end
    
    erb :dashboard
  rescue StandardError => e
    puts "Error: #{e.message}"
    redirect '/login'
  end
end

get '/logout' do
  response.delete_cookie(:token)
  redirect '/login'
end
