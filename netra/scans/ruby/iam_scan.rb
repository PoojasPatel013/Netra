#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'
require 'openssl'

# IAM & Session Scanner (Ruby Version)
# Checks for Weak Cookies and Missing Headers

target = ARGV[0]
if target.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

target = "http://" + target unless target.start_with?("http")
vulnerabilities = []

begin
  uri = URI.parse(target)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = 10
  http.read_timeout = 10
  
  request = Net::HTTP::Get.new(uri.request_uri)
  response = http.request(request)
  
  # 1. Analyze Set-Cookie Headers
  cookies = response.get_fields('set-cookie')
  if cookies
    cookies.each do |cookie|
      issues = []
      
      # Check flags
      unless cookie.downcase.include?("secure")
        # Only flag missing secure if target is https, or generally weak guidance
        issues << "Missing Secure Flag" if uri.scheme == "https"
      end
      
      unless cookie.downcase.include?("httponly")
        issues << "Missing HttpOnly Flag"
      end
      
      unless cookie.downcase.include?("samesite")
        issues << "Missing SameSite Attribute"
      end
      
      # Check Entropy (Simple Length Heuristic for Ruby MVP)
      # Extract value: SESSIONID=12345; path=/
      if cookie =~ /=(.*?);/
          val = $1
          if val && val.length < 8
              issues << "Weak Cookie Entropy (Too Short)"
          end
      end

      if issues.any?
        vulnerabilities << {
          type: "Weak Session Cookie",
          severity: "Medium",
          details: "Issues found in cookie: #{issues.join(', ')}",
          evidence: cookie,
          source: "RubyEngine"
        }
      end
    end
  end
  
  # 2. Check for Basic Auth
  if response['www-authenticate']
     vulnerabilities << {
        type: "Basic Authentication Detected",
        severity: "Low",
        details: "Server requests Basic Auth. Ensure this is over HTTPS.",
        evidence: response['www-authenticate'],
        source: "RubyEngine"
     }
  end

  # 3. OAuth & SAML Detection (Feature D)
  # Check for common OAuth endpoints
  oauth_paths = ["/oauth/authorize", "/login/oauth/authorize", "/auth/realms"]
  oauth_paths.each do |path|
      req = Net::HTTP::Get.new(path)
      res = http.request(req)
      if res.code == "200" || res.code == "302"
          vulnerabilities << {
            type: "OAuth Endpoint Discovered",
            severity: "Info",
            details: "Found OAuth authorization endpoint at #{path}. Check for Open Redirects.",
            evidence: "Status: #{res.code}",
            source: "RubyEngine"
          }
          
          # Check for Open Redirect (Simple Probe)
          # We try to redirect to example.com
          probe = "#{path}?redirect_uri=http://example.com&response_type=code&client_id=test"
          probe_req = Net::HTTP::Get.new(probe)
          probe_res = http.request(probe_req)
          if probe_res['location'] && probe_res['location'].include?("example.com")
             vulnerabilities << {
                type: "OAuth Open Redirect",
                severity: "High",
                details: "The OAuth endpoint allows arbitrary redirects via 'redirect_uri'.",
                evidence: "Redirected to: #{probe_res['location']}",
                source: "RubyEngine"
             }
          end
      end
  end

  # Check for SAML
  saml_paths = ["/saml/sso", "/SamlService", "/sso/saml"]
  saml_paths.each do |path|
      req = Net::HTTP::Get.new(path)
      res = http.request(req)
      if res.code == "200" || res.body.include?("SAMLRequest")
          vulnerabilities << {
             type: "SAML Endpoint Found",
             severity: "Info",
             details: "SAML SSO endpoint detected at #{path}. Verify XML Signature validation.",
             evidence: path,
             source: "RubyEngine"
          }
      end
  end

rescue => e
  # Return empty if connection fails
end

puts JSON.generate({
  script: "iam_scan.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
