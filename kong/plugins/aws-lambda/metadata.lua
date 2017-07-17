-- Connects with the ec2 metadata service
-- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html

local cache require "kong.tools.database_cache"
local cjson = require "cjson.safe"
local http = require "resty.http"

local _M = {}

local METADATA_URL = "http://169.254.169.254/latest/meta-data/"
local CREDENTIALS_URL = METADATA_URL.."iam/security-credentials/"
local DATE_PATTERN = "(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)Z"

function _M.get_credentials(role)
  local cached_value = cache.get("aws-lambda.credentials."..role)
  if cached_value then
    return cached_value, nil
  end

  local client = http.new()
  client:connect("169.254.169.254", 80)
  client:set_timeout(5000)
  local res, err = client:request {
    method = "GET",
    path = CREDENTIALS_URL..role,
  }
  if err then
    return nil, err
  end

  local json, err = cjson.decode(res.body)
  if err then
    return nil, err
  end

  local ttl = ttl_for_expiration(json["Expiration"])
  local cached, err = cache.set("aws-lambda.credentials."..role, json, ttl)
  return json, err
end

function _M.convert_datestr(datestr)
  local expiry_year, expiry_month, expiry_day, expiry_hour, expiry_minute, expiry_seconds = DATE_PATTERN:match(datestr)
  return os.time({year = expiry_year, month = expiry_month, day = expiry_day, hour = expiry_hour, min = expiry_minute, sec = expiry_seconds})
end

function _M.ttl_for_expiration(expiration)
  local ttl = os.difftime(os.time(), convert_datestr(json["Expiration"]))
  -- Amazon recommends expiring the cached credential 15 minutes *before* the expiration time.
  if ttl > 900 then
    ttl = ttl - 900
  end

  return ttl
end

function _M.credentials(role)
  if role == nil then
    return nil, "No instance role specified."
  end

  local credentials, err = get_credentials(role)
  if err then
    return nil, err
  end

  return {
    access_key = credentials["AccessKeyId"],
    secret_key = credentials["SecretKeyId"],
  }, nil
end

return _M
