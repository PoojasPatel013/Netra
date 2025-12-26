#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'
require 'set'

# Zombie API Scanner (Ruby + Python ML Hybrid)
# Scrapes JS files, extracts strings, and asks Python ML Engine to classify them.

target_raw = ARGV[0]
if target_raw.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

# Normalize URL
target_url = target_raw.start_with?("http") ? target_raw : "http://#{target_raw}"
uri = URI.parse(target_url)
base_url = "#{uri.scheme}://#{uri.host}#{uri.port ? ":#{uri.port}" : ""}"

vulnerabilities = []
scanned_count = 0

begin
  # 1. Fetch Index
  response = Net::HTTP.get_response(uri)
  if response.is_a?(Net::HTTPSuccess)
    html = response.body
    
    # 2. Extract JS Links
    js_links = html.scan(/src=["'](.*?.js)["']/).flatten.uniq
    
    js_links.first(5).each do |link|
      full_link = link.start_with?("http") ? link : "#{base_url}/#{link.sub(/^\//, '')}"
      
      begin
         js_res = Net::HTTP.get_response(URI.parse(full_link))
         if js_res.is_a?(Net::HTTPSuccess)
            js_code = js_res.body
            
            # 3. Extract Candidates (Strings that look like paths)
            # Regex: Strings starting with /
            candidates = js_code.scan(/["'](\/[^"'\s]+)["']/).flatten.uniq
            
            if candidates.any?
               # 4. Ask Python ML Brain (The Hybrid Bridge)
               ml_uri = URI.parse("http://localhost:8000/internal/ml/predict-zombie")
               http = Net::HTTP.new(ml_uri.host, ml_uri.port)
               req = Net::HTTP::Post.new(ml_uri.path, {'Content-Type' => 'application/json'})
               req.body = { candidates: candidates }.to_json
               
               ml_res = http.request(req)
               if ml_res.is_a?(Net::HTTPSuccess)
                  ml_data = JSON.parse(ml_res.body)
                  positives = ml_data["positives"] || []
                  
                  positives.each do |item|
                      # item is now a hash: { "path": "...", "commentary": "..." }
                      path = item["path"]
                      comment = item["commentary"]
                      
                      vulnerabilities << {
                        type: "Shadow API (Zombie Endpoint)",
                        severity: "High",
                        details: "Found '#{path}'. Neural Engine Analysis: \"#{comment}\"",
                        evidence: path,
                        source: "RubyScanner+TinyLLM"
                      }
                  end
               end
            end
         end
      rescue => e
         # Ignore fetch errors
      end
    end
  end
rescue => e
  # Ignore root errors
end

result = {
  script: "zombie_scan.rb",
  target: target_url,
  vulnerabilities: vulnerabilities
}

puts JSON.generate(result)
