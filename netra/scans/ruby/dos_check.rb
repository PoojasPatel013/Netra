#!/usr/bin/env ruby
require 'json'
require 'socket'
require 'timeout'
require 'uri'

# Slowloris Vulnerability Checker
# Checks if the server keeps connections open for partial requests.
# This indicates susceptibility to DoS/Crash attacks.

target_raw = ARGV[0]
if target_raw.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

# Extract hostname
if target_raw.include?("://")
  target_host = URI.parse(target_raw).host
else
  target_host = target_raw
end

vulnerabilities = []

begin
  # Timeout check: If we can hold a socket for 5 seconds, it might be vulnerable.
  Timeout.timeout(10) do
    # Determine port and scheme
    uri = URI.parse(target_raw.include?("://") ? target_raw : "http://#{target_raw}")
    port = uri.port || (uri.scheme == "https" ? 443 : 80)
    host = uri.host

    s = TCPSocket.new(host, port)
    
    if uri.scheme == "https"
        ssl_context = OpenSSL::SSL::SSLContext.new
        ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        s = OpenSSL::SSL::SSLSocket.new(s, ssl_context)
        s.sync_close = true
        s.connect
    end
    
    # Send partial header
    s.write("GET / HTTP/1.0\r\n")
    s.write("Host: #{host}\r\n")
    s.write("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n")
    s.write("Content-Length: 42\r\n")
    # We DO NOT send the final \r\n\r\n
    
    # Wait to see if server closes connection
    sleep 5
    
    # If we are here, the server kept it open.
    header_check = s.write("X-a: b\r\n") # Send keep-alive byte
    
    if header_check > 0
       vulnerabilities << {
          type: "DoS Susceptibility (Slowloris)",
          severity: "High",
          details: "Server accepted incomplete HTTP headers for > 5 seconds. Vulnerable to Slowloris DoS attacks.",
          evidence: "Socket held open for 5s with partial request.",
          source: "RubyEngine"
        }
    end
    s.close
  end
rescue Timeout::Error
  # Timed out implies it might be hanging (which is what we tested for) or network lag.
rescue Errno::ECONNRESET, Errno::EPIPE
  # Server closed connection - Good! Secure against Slowloris.
rescue => e
  # Connection failed
end

puts JSON.generate({
  script: "dos_check.rb",
  target: target_host,
  vulnerabilities: vulnerabilities
})
