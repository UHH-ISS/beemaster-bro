module beemaster;

export {
  type AlertInfo: record {
    timestamp: time;
    incident_type: string;
    protocol: string;
    source_ip: string;
    source_port: port;
    destination_ip: addr;
    destination_port: port;
  };
}
