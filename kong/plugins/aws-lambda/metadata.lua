-- Connects with the ec2 metadata service
-- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html

local cjson = require "cjson.safe"
local http = require "resty.http"

local _M = {}

local METADATA_URL = "http://169.254.169.254/latest/meta-data/"
local CREDENTIALS_URL = METADATA_URL.."iam/security-credentials/"

function _M.get_credentials(role)
  if role == nil then
    return nil, "No instance role specified."
  end

  local client = http.new()
  client:connect("http://169.254.169.254", 80)
  client:set_timeout(5000)
  local res, err = client:request {
    method = "GET",
    path = CREDENTIALS_URL..role,
  }
  if err then
    return nil, err
  end

  local json, err = cjson.decode(res.body)
  return json, err
end

function _M.credentials(role)
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
