#!/usr/bin/ruby

require 'rubygems'
require 'base64'
require 'openssl'
require 'digest/sha1'
require 'time'
require 'curb'
require 'nokogiri'
require 'fileutils'
require 'digest/md5'

def usage
  puts "Before running this script you must export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
  puts "Usage: s3clone <source_bucket_name> <target_bucket_name>"
end


if ENV['AWS_ACCESS_KEY_ID'].nil? || ENV['AWS_SECRET_ACCESS_KEY'].nil?
  usage
  exit 1
end

AWS_ACCESS_KEY_ID = ENV['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = ENV['AWS_SECRET_ACCESS_KEY']
REQUEST_HOST = 's3.amazonaws.com'
DEBUG = false
STDOUT.sync = true

def CanonicalizedAmzHeaders
  return ''
end

def get_string_to_sign(date_to_sign, canonicalized_resource, request_method, content_type)
  content_md5 = ''
  canonicalized_amz_headers  = ''
  string_to_sign = request_method + "\n" +
	                 content_md5 + "\n" +
                   content_type + "\n" +
                   date_to_sign + "\n" +
                   canonicalized_amz_headers +
                   canonicalized_resource
         
  return string_to_sign
end

def get_canonicalized_resource(request_url)
  return request_url
end

def get_signature(date_to_sign, canonicalized_resource, request_method, content_type)
  digest = OpenSSL::Digest::Digest.new('sha1')
  b64_hmac = Base64.encode64(
               OpenSSL::HMAC.digest(digest, 
                                    AWS_SECRET_ACCESS_KEY,
                                    get_string_to_sign(date_to_sign, canonicalized_resource, request_method, content_type)
                                    )).strip
  return b64_hmac
end

def send_request(request_url, attributes = '', request_method='GET', headers = {})
  canonicalized_resource = get_canonicalized_resource(request_url)

  host = headers[:Host] || REQUEST_HOST
  c = Curl::Easy.new(host + request_url + attributes)
  c.headers["Host"] = host
  c.headers["Date"] = Time.now.httpdate
  if headers["Content-Type"]
    c.headers["Content-Type"] = headers["Content-Type"]
  end
  c.headers["Authorization"] = "AWS " + 
                               AWS_ACCESS_KEY_ID + ":" +
                               get_signature(c.headers["Date"],
                                             canonicalized_resource,
                                             request_method,
                                             headers["Content-Type"].nil? ? '' : headers["Content-Type"]
                                             )
  download_attempt = 0
  begin
    c.perform
  rescue Curl::Err::GotNothingError
    print "#{request_url} download failed. "
    if download_attempt < 3
      puts "Trying again..."
      download_try = download_attempt + 1
      retry
    else
      puts "Giving up."
      c = nil
    end    
  end                       
  return c
end

def is_a_directory(key)
  if (key =~ /.*\/$/)
    return true
  else 
    return false
  end
end

def store_file(raw_file, path)
  if not File.directory?(File.dirname(path))
    File.mkdir_p File.dirname(path)
  end
  if File.directory?(path)
    path = "#{path}_S3TMPFILE"
  end
  File.open(path, 'w') { |f|
    f.write(raw_file)
  }
end

def parse_aws_response(raw_xml)
  bucket = Array.new
  xml = Nokogiri::XML(raw_xml)
  current_bucket = xml.css("ListBucketResult Name")[0].text
  truncated = xml.css("ListBucketResult IsTruncated")[0].text

  contents = xml.css("Contents")
  contents.each { |node|
    content_hash = Hash.new
    key = node.css("Key").first
    if is_a_directory(key.text)
      content_hash[:type] = "D"
    else
      content_hash[:type] = "A"
      bucket << content_hash      
    end
    content_hash[:modified] = node.css("LastModified").first.text
    content_hash[:path] = key.text
#    bucket << content_hash
  }
  puts "TRUNC: #{truncated}"
  if truncated == "true"
    puts "TRUNCATED"
    return bucket, bucket[-1][:path]
  else
    return bucket, false
  end
end

def process_request(bucket_name)
  bucket = Array.new
  marker = ''
  while marker
    if marker && !marker.empty?
      attributes = "?marker=#{marker}"
    else
      attributes  = ''
    end
    url = "/" + bucket_name + "/"
    aws_response = send_request(url, attributes)
    puts aws_response.header_str if DEBUG
    aux_bucket, marker = parse_aws_response(aws_response.body_str)
    bucket = bucket + aux_bucket
  end
  return bucket
end

def upload_element(element, buckets_prefix)
  request_url = "/#{element[:path]}"
  canonicalized_resource = get_canonicalized_resource("/" + element[:target_bucket] + request_url)
  
  host = element[:target_bucket] + "." + REQUEST_HOST
  c = Curl::Easy.new(host + request_url)
  c.headers["Host"] = host
  c.headers["Date"] = Time.now.httpdate
  c.headers["Content-Type"] = element[:mime]
  c.headers["Authorization"] = "AWS " + 
                               AWS_ACCESS_KEY_ID + ":" +
                               get_signature(c.headers["Date"],
                                             canonicalized_resource,
                                             "PUT",
                                             element[:mime]
                                             )

  if File.file?("#{buckets_prefix}/#{element[:target_bucket]}#{request_url}")
    File.open("#{buckets_prefix}/#{element[:target_bucket]}#{request_url}", 'r') { |f|
      c.http_put(f)
    }
  else
    File.open("#{buckets_prefix}/#{element[:target_bucket]}#{request_url}_S3TMPFILE", 'r') { |f|
      c.http_put(f)
    }
  end
end

def update_acl(element)
  request_url = "/#{element[:path]}?acl"
  canonicalized_resource = get_canonicalized_resource("/" + element[:target_bucket] + request_url)
  
  host = element[:target_bucket] + "." + REQUEST_HOST
  c = Curl::Easy.new(host + request_url)
  c.headers["Host"] = host
  c.headers["Date"] = Time.now.httpdate
  c.headers["Authorization"] = "AWS " + 
                               AWS_ACCESS_KEY_ID + ":" +
                               get_signature(c.headers["Date"],
                                             canonicalized_resource,
                                             "PUT",
                                             ""
                                             )
  c.http_put(element[:acl])
end

def compare_buckets(source_bucket, target_bucket)
  incremental_list = Array.new
  path_search_array = target_bucket[:bucket_data].collect { |element| element[:path]}
  modified_search_array = target_bucket[:bucket_data].collect { |element| element[:modified]}  
  source_bucket[:bucket_data].each { |source_element|
    updateable = true
    if element_position = path_search_array.index(source_element[:path])
      if Time.parse(source_element[:modified]) <= Time.parse(modified_search_array[element_position])
        updateable = false
      end
    end
    if updateable
      incremental_list << {:source_bucket => source_bucket[:bucket_name],
                           :target_bucket => target_bucket[:bucket_name],
                           :type => source_element[:type],
                           :path => source_element[:path]
                          }    
    end
  }
  return incremental_list
end

def check_args(args)
  if args.nil? || args.empty? || args.length < 2
    return false
  else
    return true
  end
end

def download_element(element, buckets_prefix)
  FileUtils.mkdir_p "#{buckets_prefix}/#{element[:target_bucket]}/#{File.dirname(element[:path])}"
  aws_response = send_request("/" + element[:source_bucket] + "/" + element[:path])
  if aws_response.nil?
    return false
  else
    element[:mime] = aws_response.header_str.match(/Content-Type: (.*)$/)[1].strip      
    store_file(aws_response.body_str, "#{buckets_prefix}/#{element[:target_bucket]}/#{element[:path]}")    
    return true
  end
end

def download_element_acl(element)
  aws_response_acl = send_request("/" + element[:source_bucket] + "/" + element[:path] + "?acl")
  if aws_response_acl
    element[:acl] = aws_response_acl.body_str
  end
end

def sync_elements(elements, buckets_prefix)
  FileUtils.mkdir_p "#{buckets_prefix}/#{elements[0][:target_bucket]}"
  elements.each { |element|
    puts "Syncing #{element[:path]}"
    if is_a_directory(element[:path])
      FileUtils.mkdir_p "#{buckets_prefix}/#{element[:target_bucket]}/#{element[:path]}"
    else
      if download_element(element, buckets_prefix)      
        if not is_a_directory(element[:path])
          upload_element(element, buckets_prefix)
          download_element_acl(element)            
          if not element[:acl].nil?
            update_acl(element)
          end          
        end
      end
    end
  }
end

buckets_prefix = 'buckets'
FileUtils.rm_rf buckets_prefix
FileUtils.mkdir_p buckets_prefix


if not check_args(ARGV) 
  usage
  exit 1
end
buckets = Array.new

ARGV.each { |arg|
  puts "Fetching bucket #{arg} elements"
  buckets << {:bucket_name => arg, :bucket_data => process_request(arg)}
}
buckets.each { |bucket|
  if not buckets[0] == bucket
    puts "Comparing buckets"
    upload_list = compare_buckets(buckets[0], bucket)
    if not upload_list.empty?
      puts "Syncing elements"
      sync_elements(upload_list.sort_by {|element| element[:type]}.reverse, buckets_prefix)
    end
  end
}
