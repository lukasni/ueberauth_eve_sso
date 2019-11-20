defmodule Ueberauth.Strategy.EVESSO do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with EVE SSO v2.

  ### Setup

  Create an SSO Application on the [EVE Developers page](https://developers.eveonline.com/).

  After registering an application get the client id and secret key from the application details page.

  Include the credentials in the configuration for EVESSO

      config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: System.get_env("EVESSO_CLIENT_ID"),
        client_secret: System.get_env("EVESSO_SECRET_KEY")

  If you haven't already, create a pipeline and set up routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider/callback", AuthController, :callback
      end

  Create an endpoint for the callback where you will handle the Ueberauth.Auth struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback_phase(%{assigns: %{ueberauth_failure: fails}} = conn, _params) do
          #do things with the failure
        end

        def callback_phase(%{assigns: %{ueberauth_auth: auth}} = conn, params) do
          # do things with the auth
        end
      end

  You can edit the behaviour of the Strategy by including some options when you register your provider

  To set the `uid_field`

      config :ueberauth, Ueberauth,
        providers: [
          evesso: {Ueberauth.Strategy.EVESSO, [uid_field: :character_id]}
        ]

  Default is `:owner_hash`, others available are `:character_id` and `:name`

  To set the default scopes:

      config :ueberauth, Ueberauth,
        providers: [
          evesso: {Ueberauth.Strategy.EVESSO, [default_scope: "esi-clones.read_implants.v1 esi-characters.read_notifications.v1"]}
        ]

  Default is empty ("") which doesn't grant any extra permissions beyond public endpoints but enables you to verify character ownership.
  Scopes are provided as a space-separated list.
  """
  use Ueberauth.Strategy,
    uid_field: :owner_hash,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.EVESSO.OAuth

  alias Ueberauth.Auth.{Info, Credentials, Extra}

  @doc """
  Handles the initial redirect to the EVE SSO authentication page

  To customize the scopes that are requested from SSO include them as part of your url:

      "/auth/evesso?scope=esi-clones.read_implants.v1"

  EVE SSO v2 also requires a `state` param that will be returned and can be used to guard against MITM attacks.
  """
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

  @doc """
  Handles the callback from EVE SSO. When there is a failure from EVE SSO the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned in the token is returned in the Ueberauth.Auth struct.
  """
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

  @doc """
  Handles failure of SSO where no auth code is returned
  """
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw SSO response around during the callback phase
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:evesso_token, nil)
    |> put_private(:evesso_user, nil)
  end

  @doc """
  Fetches the uid field from the token payload. This defaults to the option `uid_field` which in turn defaults to `owner_hash`
  """
  def uid(conn) do
    conn |> option(:uid_field) |> fetch_uid(conn)
  end

  @doc """
  Includes the credentials from the SSO response.
  """
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

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.evesso_user

    %Info{
      name: user.name
    }
  end

  @doc """
  Stores the raw information, including the token, obtained from the SSO callback.
  """
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
    character_id =
      verify["sub"]
      |> String.replace("CHARACTER:EVE:", "")
      |> String.to_integer()

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
