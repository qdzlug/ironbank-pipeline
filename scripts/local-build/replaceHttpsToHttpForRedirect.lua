function envoy_on_response(response_handle)
  local headers = response_handle:headers()
  local location = headers:get('location')
  if location ~= nil and string.match(location, "https") then
    local newlocation = string.gsub(location,"^https", "http")
    response_handle:headers():replace("location", newlocation)
  end
  local authenticate = headers:get('www-authenticate')
  if authenticate ~= nil and string.match(authenticate, "https") then
    local newauthenticate = string.gsub(authenticate,"https", "http")
    response_handle:headers():replace("www-authenticate", newauthenticate)
  end
end
