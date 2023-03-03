local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()

local csrf = require("kong.plugins.oidc.csrf")
local filter = require("kong.plugins.oidc.filter")
local multitenancy = require("kong.plugins.oidc.multitenancy")
local routes = require("kong.plugins.oidc.routes")
local session = require("kong.plugins.oidc.session")
local token_validator = require("kong.plugins.oidc.token_validator")
local utils = require("kong.plugins.oidc.utils")

OidcHandler.PRIORITY = 1000

function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldIgnoreRequest(oidcConfig) then
    kong.log.debug("OidcHandler ignoring request, path: " .. ngx.var.request_uri)
    kong.log.debug("OidcHandler done")
    return
  end

  if routes.shouldIgnoreRoute(oidcConfig) then
    kong.log.debug("OidcHandler ignoring route: " .. kong.router.get_route().name)
    kong.log.debug("OidcHandler done")
    return
  end

  session.configure(config)
  oidc(oidcConfig)

  kong.log.debug("OidcHandler done")
end

function oidc(oidcConfig)

  oidcConfig.lifecycle = { on_authenticated = on_authenticated }
  kong.log.debug("OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local unauth_action = nil

  if oidcConfig.bearer_only == "yes" then
    kong.log.debug("set unauthaction to pass")
    unauth_action = "pass"
  end

  local res, err = require("resty.openidc").authenticate(oidcConfig, nil, unauth_action)

  if err then
    kong.log.warn("OidcHandler authenticate failed: " .. err)
    if oidcConfig.bearer_only == "yes" then
      kong.log.debug("skipping redirect, bearer only enabled")
      ngx.exit(200, err, ngx.HTTP_OK)
    end
    if oidcConfig.recovery_page_path then
      kong.log.debug("Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  if not res and oidcConfig.bearer_only == "yes" then
    kong.response.clear_header("Set-Cookie")
  end

  enhance_response(res, oidcConfig)
  return res
end

function on_authenticated(session)
  csrf.set(session)
  session.data.selected_tenant_force = "false"
end

function enhance_response(response, oidcConfig)
  if not response then return end
  if (response.access_token) then
      utils.injectBearerAccessToken(response.access_token)
  end
end

return OidcHandler