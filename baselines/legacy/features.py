from __future__ import annotations

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = {
    'flow_duration_s', 'packets', 'bytes', 'syn_count', 'ack_count', 'rst_count',
    'failed_logins', 'unique_dst_ports_60s', 'connections_60s', 'dst_port',
}
COUNT_COLUMNS = REQUIRED_COLUMNS - {'flow_duration_s'}


def extract_features(flows: pd.DataFrame) -> pd.DataFrame:
    """Reject invalid observations before calculating rates; never impute bad traffic as normal."""
    if flows.columns.duplicated().any():
        raise ValueError('Duplicate column names are not allowed.')
    missing = sorted(REQUIRED_COLUMNS - set(flows.columns))
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")
    if flows.empty:
        raise ValueError('Input contains no flow records.')
    featured = flows.copy()
    for column in sorted(REQUIRED_COLUMNS):
        values = pd.to_numeric(featured[column], errors='coerce')
        invalid = ~np.isfinite(values.to_numpy(dtype=float))
        if invalid.any():
            rows = (np.flatnonzero(invalid)[:5] + 1).tolist()
            raise ValueError(f'{column}: require finite numeric values; invalid data rows {rows}.')
        if (values < 0).any():
            raise ValueError(f'{column}: negative values are not allowed.')
        if column in COUNT_COLUMNS and (values % 1 != 0).any():
            raise ValueError(f'{column}: require integer counts or ports.')
        featured[column] = values
    if (featured['flow_duration_s'] <= 0).any():
        raise ValueError('flow_duration_s must be greater than zero.')
    if (featured['packets'] <= 0).any():
        raise ValueError('packets must be greater than zero.')
    if (featured['dst_port'] > 65535).any():
        raise ValueError('dst_port must be between 0 and 65535.')
    for column in ['syn_count', 'ack_count', 'rst_count']:
        if (featured[column] > featured['packets']).any():
            raise ValueError(f'{column} cannot exceed packets.')
    if (featured['unique_dst_ports_60s'] > 65536).any():
        raise ValueError('unique_dst_ports_60s cannot exceed 65536.')
    if (featured['unique_dst_ports_60s'] > featured['connections_60s']).any():
        raise ValueError('unique_dst_ports_60s cannot exceed connections_60s for the same source/window.')
    if 'protocol' in featured:
        protocol = featured['protocol'].astype(str).str.upper()
        if (~protocol.isin(['TCP', 'UDP'])).any():
            raise ValueError('protocol, when supplied, must be TCP or UDP.')
        udp_flags = featured[['syn_count', 'ack_count', 'rst_count']].sum(axis=1)
        if ((protocol == 'UDP') & (udp_flags != 0)).any():
            raise ValueError('UDP records cannot contain TCP flag counts.')
        featured['protocol'] = protocol
    duration, packets = featured['flow_duration_s'], featured['packets']
    featured['packet_rate'] = packets / duration
    featured['byte_rate'] = featured['bytes'] / duration
    featured['avg_packet_size'] = featured['bytes'] / packets
    featured['syn_ratio'] = featured['syn_count'] / packets
    featured['rst_ratio'] = featured['rst_count'] / packets
    featured['is_auth_service'] = featured['dst_port'].isin([21, 22, 23, 3389]).astype(int)
    derived = ['packet_rate', 'byte_rate', 'avg_packet_size', 'syn_ratio', 'rst_ratio']
    if not np.isfinite(featured[derived].to_numpy()).all():
        raise ValueError('Derived features overflowed; check the magnitude of counters and duration.')
    return featured
