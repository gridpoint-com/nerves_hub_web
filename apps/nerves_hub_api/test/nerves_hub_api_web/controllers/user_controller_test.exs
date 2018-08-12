defmodule NervesHubAPIWeb.UserControllerTest do
  use NervesHubAPIWeb.ConnCase

  alias NervesHubCore.Fixtures
  alias NervesHubCore.Certificate
  alias NervesHubCore.Accounts

  test "me", %{conn: conn, user: user} do
    conn = get(conn, user_path(conn, :me))

    assert json_response(conn, 200)["data"] == %{
             "name" => user.name,
             "email" => user.email
           }
  end

  test "register new account", %{} do
    conn = build_conn()
    body = %{name: "test", password: "12345678", email: "test@test.com"}
    conn = post(conn, user_path(conn, :register), body)

    assert json_response(conn, 200)["data"] == %{
             "name" => body.name,
             "email" => body.email
           }
  end

  @tag :ca_integration
  test "sign new registration certificates" do
    csr =
      Fixtures.path()
      |> Path.join("cfssl/user-csr.pem")
      |> File.read!()
      |> Base.encode64()

    params =
      Fixtures.user_params()
      |> Map.take([:email, :password])
      |> Map.put(:csr, csr)
      |> Map.put(:description, "test-machine")

    conn = build_conn()

    conn = post(conn, user_path(conn, :sign), params)
    resp_data = json_response(conn, 200)["data"]
    assert %{"cert" => cert} = resp_data

    {:ok, serial} = Certificate.get_serial_number(cert)

    user = Accounts.get_user_with_certificate_serial(serial)
    assert user.email == params.email
  end
end
