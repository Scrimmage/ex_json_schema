defmodule ExJsonSchema.Validator.Format do
  alias ExJsonSchema.Validator

  @date_time_regex ~r/^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$/
  @email_regex ~r<^[\w!#$%&'*+/=?`{|}~^-]+(?:\.[\w!#$%&'*+/=?`{|}~^-]+)*@(?:[A-Z0-9-]+\.)+[A-Z]{2,}$>i
  @hostname_regex ~r/^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$/i
  @ipv4_regex ~r/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  @ipv6_regex ~r/^(?:(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|(?:[A-F0-9]{1,4}:){7}:|:(:[A-F0-9]{1,4}){7})$/i

  @iri_gruber_v2 ~r'(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'u
  @iri_stephenhay ~r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'ui
  @iri_diegoperini ~r'^(?:(?:https?|ftp)://)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\x{00a1}-\x{ffff}0-9]+-?)*[a-z\x{00a1}-\x{ffff}0-9]+)(?:\.(?:[a-z\x{00a1}-\x{ffff}0-9]+-?)*[a-z\x{00a1}-\x{ffff}0-9]+)*(?:\.(?:[a-z\x{00a1}-\x{ffff}]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$'iu

  @iri_regex @iri_diegoperini
  
  @spec validate(String.t, ExJsonSchema.data) :: Validator.errors_with_list_paths
  def validate(format, data) when is_binary(data) do
    do_validate(format, data)
  end

  def validate(_, _), do: []

  defp do_validate("date-time", data) do
    validate_with_regex(data, @date_time_regex, fn data -> "Expected #{inspect(data)} to be a valid ISO 8601 date-time." end)
  end

  defp do_validate("email", data) do
    validate_with_regex(data, @email_regex, fn data -> "Expected #{inspect(data)} to be an email address." end)
  end

  defp do_validate("hostname", data) do
    validate_with_regex(data, @hostname_regex, fn data -> "Expected #{inspect(data)} to be a host name." end)
  end

  defp do_validate("ipv4", data) do
    validate_with_regex(data, @ipv4_regex, fn data -> "Expected #{inspect(data)} to be an IPv4 address." end)
  end

  defp do_validate("ipv6", data) do
    validate_with_regex(data, @ipv6_regex, fn data -> "Expected #{inspect(data)} to be an IPv6 address." end)
  end

  defp do_validate("iri", data) do
    validate_with_regex(data, @iri_regex, fn data -> "Expected #{inspect(data)} to be an IRI." end)
  end

  defp do_validate(_, _) do
    []
  end

  defp validate_with_regex(data, regex, failure_message_fun) do
    case Regex.match?(regex, data) do
      true -> []
      false -> [{failure_message_fun.(data), []}]
    end
  end
end
