defmodule NervesHub.DeviceSSLTransport do
  @moduledoc """
  SSL transport for device certificate authentication

  This transport exists to rate limit incoming SSL connections _before_ any
  ssl work has started. This let's us shed incoming devices before we waste
  a lot of resources on denying them midway through the SSL connection in
  the `NervesHub.SSL.verify_fun/3`

  See `handshake/1` for the main change. All other function are delegated back to
  `ThousandIsland.Transports.SSL`
  """

  @behaviour ThousandIsland.Transport

  alias ThousandIsland.Transports.SSL

  @impl ThousandIsland.Transport
  defdelegate listen(port, user_options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate accept(listener_socket), to: SSL

  @impl ThousandIsland.Transport
  def handshake(socket) do
    if NervesHub.RateLimit.increment() do
      :telemetry.execute([:nerves_hub, :rate_limit, :accepted], %{count: 1})

      # Capture the peer IP BEFORE the handshake. TLS handshake failures — e.g.
      # `bad_certificate` generated at the `wait_cert_verify` state when a device's
      # CertificateVerify signature fails (which happens AFTER our `verify_fun` ran
      # and already bumped the device cert `last_used`) — are otherwise anonymous:
      # the Erlang SSL alert carries no client identity, so we cannot attribute the
      # ~thousand/hour TLS failures to a specific device. Grabbing peername up front
      # (the TCP connection exists post-accept) means we still have the IP even if the
      # failed handshake tears the socket down. Cross-reference with NLB flow logs
      # (client IP preserved) to map IP -> device. See sc-225223.
      peer_ip = peer_ip(socket)

      case SSL.handshake(socket) do
        {:ok, _} = ok ->
          ok

        {:error, reason} = error ->
          :telemetry.execute([:nerves_hub, :devices, :tls_handshake_error], %{count: 1}, %{
            reason: inspect(reason),
            peer_ip: peer_ip
          })

          error
      end
    else
      :telemetry.execute([:nerves_hub, :rate_limit, :rejected], %{count: 1})

      {:error, :closed}
    end
  end

  defp peer_ip(socket) do
    case SSL.peername(socket) do
      {:ok, {ip, _port}} -> ip |> :inet.ntoa() |> List.to_string()
      _ -> nil
    end
  end

  @impl ThousandIsland.Transport
  defdelegate upgrade(socket, opts), to: SSL

  @impl ThousandIsland.Transport
  defdelegate controlling_process(socket, pid), to: SSL

  @impl ThousandIsland.Transport
  defdelegate recv(socket, length, timeout), to: SSL

  @impl ThousandIsland.Transport
  defdelegate send(socket, data), to: SSL

  @impl ThousandIsland.Transport
  defdelegate sendfile(socket, filename, offset, length), to: SSL

  @impl ThousandIsland.Transport
  defdelegate getopts(socket, options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate setopts(socket, options), to: SSL

  @impl ThousandIsland.Transport
  defdelegate shutdown(socket, way), to: SSL

  @impl ThousandIsland.Transport
  defdelegate close(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate sockname(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate peername(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate peercert(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate secure?(), to: SSL

  @impl ThousandIsland.Transport
  defdelegate getstat(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate negotiated_protocol(socket), to: SSL

  @impl ThousandIsland.Transport
  defdelegate connection_information(socket), to: SSL
end
