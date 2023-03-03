local typedefs = require "kong.db.schema.typedefs"

return {
  name = "oidc",
  fields = {
    {
      consumer = typedefs.no_consumer
    },
    {
      config = {
        type = "record",
        fields = {
          { client_id                           = { type = "string", required = true } },
          { client_secret                       = { type = "string", required = true } },
          { discovery                           = { type = "string", required = true, default = "https://.well-known/openid-configuration" } },
          { valid_issuers                       = {
                                                    type = "array",
                                                    required = false,
                                                    elements = { type = "string" }
                                                  } },
          { introspection_endpoint                   = { type = "string", required = false } },
          { timeout                                  = { type = "number", required = false } },
          { introspection_endpoint_auth_method       = { type = "string", required = false } },
          { bearer_only                              = { type = "string", required = true, default = "no" } },
          { realm                                    = { type = "string", required = true, default = "kong" } },
          { redirect_uri_path                        = { type = "string" } },
          { scope                                    = { type = "string", required = true, default = "openid" } },
          { response_type                            = { type = "string", required = true, default = "code" } },
          { ssl_verify                               = { type = "string", required = true, default = "no" } },
          { token_endpoint_auth_method               = { type = "string", required = true, default = "client_secret_post" } },
          { session_secret                           = { type = "string", required = false } },
          { recovery_page_path                       = { type = "string" } },
          { logout_path                              = { type = "string", required = false, default = '/logout' } },
          { redirect_after_logout_uri                = { type = "string", required = false, default = '/' } },
          { post_logout_redirect_uri                 = { type = "string", required = false, default = '/' } },
          { redirect_after_logout_with_id_token_hint = { type = "boolean", required = false, default = false } },
          { filters                                  = { type = "string" } },
          { ignored_routes                           = {
                                                         type = "array",
                                                        required = false,
                                                        elements = { type = "string" }
                                                       } },
          { forward_bearer_access_token              = { type = "string", required = false, default = "no"} },
        }
      }
    }
  }
}
