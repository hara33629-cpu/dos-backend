def extract_features(
    request_size,
    high_request_rate,
    small_payload,
    large_payload,
    spike_in_requests,
    repeated_access,
    unusual_user_agent,
    invalid_headers
):
    return [
        request_size,
        int(high_request_rate),
        int(small_payload),
        int(large_payload),
        int(spike_in_requests),
        int(repeated_access),
        int(unusual_user_agent),
        int(invalid_headers)
    ]
