defmodule NervesHubWeb.Live.Deployments.Index do
  use NervesHubWeb, :updated_live_view

  alias NervesHub.Deployments
  alias NervesHub.Deployments.Deployment
  alias NervesHub.Firmwares.Firmware

  @impl Phoenix.LiveView
  def mount(_params, _session, %{assigns: %{product: product}} = socket) do
    deployments = Deployments.get_deployments_by_product(product)
    counts = Deployments.get_device_counts_by_product(product)

    deployments =
      deployments
      |> Enum.sort_by(& &1.name)
      |> Enum.group_by(fn deployment ->
        deployment.firmware.platform
      end)

    socket
    |> page_title("Deployments - #{product.name}")
    |> assign(:deployments, deployments)
    |> assign(:counts, counts)
    |> ok()
  end

  defp firmware_simple_display_name(%Firmware{} = f) do
    "#{f.version} #{f.uuid}"
  end

  defp version(%Deployment{conditions: %{"version" => ""}}), do: "-"
  defp version(%Deployment{conditions: %{"version" => version}}), do: version

  defp tags(%Deployment{conditions: %{"tags" => tags}}), do: tags
end
