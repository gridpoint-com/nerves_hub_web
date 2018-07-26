defmodule NervesHubCore.FirmwaresTest do
  use NervesHubCore.DataCase

  alias NervesHubWeb.Fixtures
  alias NervesHubCore.{Firmwares, Repo}
  alias NervesHubCore.Firmwares.Firmware
  alias NervesHubCore.Deployments.Deployment
  alias NervesHubCore.Accounts.TenantKey

  alias Ecto.Changeset

  @test_firmware_path "../../test/fixtures/firmware"
  @unsigned_firmware_path Path.join(@test_firmware_path, "unsigned.fw")
  @signed_key1_firmware_path Path.join(@test_firmware_path, "signed-key1.fw")
  @signed_other_key_firmware_path Path.join(@test_firmware_path, "signed-other-key.fw")
  @corrupt_firmware_path Path.join(@test_firmware_path, "signed-other-key.fw")
  @firmware_pub_key1 %TenantKey{
    id: "key1",
    key: File.read!(Path.join(@test_firmware_path, "fwup-key1.pub"))
  }
  @firmware_pub_key2 %TenantKey{
    id: "key2",
    key: File.read!(Path.join(@test_firmware_path, "fwup-key2.pub"))
  }

  setup do
    tenant = Fixtures.tenant_fixture()
    product = Fixtures.product_fixture(tenant)
    tenant_key = Fixtures.tenant_key_fixture(tenant)
    firmware = Fixtures.firmware_fixture(tenant, tenant_key, product)
    deployment = Fixtures.deployment_fixture(tenant, firmware, product)
    device = Fixtures.device_fixture(tenant, firmware, deployment, product)

    {:ok,
     %{
       tenant: tenant,
       firmware: firmware,
       deployment: deployment,
       matching_device: device,
       product: product
     }}
  end

  def update_version_condition(%Deployment{} = deployment, version) when is_binary(version) do
    deployment
    |> Changeset.change(%{
      conditions: %{
        "tags" => deployment.conditions["tags"],
        "version" => version
      }
    })
    |> Repo.update!()
  end

  describe "NervesHubWWW.Firmwares.get_firmwares_by_product/2" do
    test "returns firmwares", %{product: %{id: product_id} = product} do
      firmwares = Firmwares.get_firmwares_by_product(product.id)

      assert [%{product_id: ^product_id}] = firmwares
    end
  end

  describe "NervesHubWWW.Firmwares.get_firmware/2" do
    test "returns firmwares", %{tenant: %{id: t_id} = tenant, firmware: %{id: f_id} = firmware} do
      {:ok, gotten_firmware} = Firmwares.get_firmware(tenant, firmware.id)

      assert %{id: ^f_id, product: %{tenant_id: ^t_id}} = gotten_firmware
    end
  end

  describe "NervesHubCore.Firmwares.verify_signature/2" do
    test "returns {:error, :no_public_keys} when no public keys are passed" do
      assert Firmwares.verify_signature(@unsigned_firmware_path, []) == {:error, :no_public_keys}

      assert Firmwares.verify_signature(@signed_key1_firmware_path, []) ==
               {:error, :no_public_keys}

      assert Firmwares.verify_signature(@signed_other_key_firmware_path, []) ==
               {:error, :no_public_keys}
    end

    test "returns {:ok, key} when signature passes" do
      assert Firmwares.verify_signature(@signed_key1_firmware_path, [@firmware_pub_key1]) ==
               {:ok, @firmware_pub_key1}

      assert Firmwares.verify_signature(@signed_key1_firmware_path, [
               @firmware_pub_key1,
               @firmware_pub_key2
             ]) == {:ok, @firmware_pub_key1}

      assert Firmwares.verify_signature(@signed_key1_firmware_path, [
               @firmware_pub_key2,
               @firmware_pub_key1
             ]) == {:ok, @firmware_pub_key1}
    end

    test "returns {:error, :invalid_signature} when signature fails" do
      assert Firmwares.verify_signature(@signed_key1_firmware_path, [@firmware_pub_key2]) ==
               {:error, :invalid_signature}

      assert Firmwares.verify_signature(@signed_other_key_firmware_path, [
               @firmware_pub_key1,
               @firmware_pub_key2
             ]) == {:error, :invalid_signature}

      assert Firmwares.verify_signature(@unsigned_firmware_path, [@firmware_pub_key1]) ==
               {:error, :invalid_signature}
    end

    test "returns {:error, :invalid_signature} on corrupt files" do
      assert Firmwares.verify_signature(@corrupt_firmware_path, [
               @firmware_pub_key1,
               @firmware_pub_key2
             ]) == {:error, :invalid_signature}
    end
  end
end