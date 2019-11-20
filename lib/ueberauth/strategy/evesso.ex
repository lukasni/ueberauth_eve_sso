defmodule Ueberauth.Strategy.EVESSO do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with EVE SSO v2.

  ### Setup

  Create an SSO Application on the [EVE Developers page](https://developers.eveonline.com/).

  After registering an application get the client id and secret key from the application details page.

  Include the credentials in the configuration for EVESSO

      config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: System.get_env("EVESSO_CLIENT_ID"),
        secret_key: System.get_env("EVESSO_SECRET_KEY")
  """
  use Ueberauth.Strategy,
    uid_field: :owner_hash,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.EVESSO.OAuth

  alias Ueberauth.Auth.{Info, Credentials, Extra}

  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn), scope: scopes]
      else
        [scope: scopes]
      end

    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code]])

    if token.access_token == nil do
      set_errors!(conn, [
        error(token.other_params["error"], token.other_params["error_description"])
      ])
    else
      fetch_user(conn, token)
    end
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:evesso_token, nil)
    |> put_private(:evesso_user, nil)
  end

  def uid(conn) do
    conn |> option(:uid_field) |> fetch_uid(conn)
  end

  def credentials(conn) do
    token = conn.private.evesso_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, " ")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  def info(conn) do
    user = conn.private.evesso_user

    %Info{
      name: user.name
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.evesso_token,
        user: conn.private.evesso_user
      }
    }
  end

  defp fetch_uid(field, conn) do
    conn.private.evesso_user[field]
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :evesso_token, token)

    with {:ok, verified} <- Ueberauth.Strategy.EVESSO.OAuth.verify(token),
         {:ok, user} <- extra_user_info(verified) do
      put_private(conn, :evesso_user, user)
    else
      {:error, reason} ->
        set_errors!(conn, error("Verify", reason))

      _err ->
        set_errors!(conn, error("Verify", "Unexpected error during verification"))
    end
  end

  defp extra_user_info(verify) do
    character_id = String.replace(verify["sub"], "CHARACTER:EVE:", "") |> String.to_integer()

    user = %{
      name: verify["name"],
      character_id: character_id,
      owner_hash: verify["owner"]
    }

    {:ok, user}
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
