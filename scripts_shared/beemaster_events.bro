module Beemaster;

@load ./beemaster_types

export {
    # ## DIONAEA EVENTS ##
    # Basic access
    global dionaea_access: event(timestamp: time, dst_ip: addr, dst_port: count,
        src_hostname: string, src_ip: addr, src_port: count, transport: string, protocol: string, connector_id: string);
    # HTTP(?) download completed
    global dionaea_download_complete: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        url: string, md5hash: string, filelocation: string, origin: string, connector_id: string);
    # HTTP(?) download offered
    global dionaea_download_offer: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        url: string, origin: string, connector_id: string);
    # FTP connection
    global dionaea_ftp: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        command: string, arguments: string, origin: string, connector_id: string);
    # MySQL command execution
    global dionaea_mysql_command: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        args: string, origin: string, connector_id: string);
    # MySQL login
    global dionaea_login: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        username: string, password: string, origin: string, connector_id: string);
    # SMB connection established(?)
    global dionaea_smb_bind: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        transfersyntax: string, uuid: string, origin: string, connector_id: string);
    # SMB file requested
    global dionaea_smb_request: event(timestamp: time, id: string, local_ip: addr, local_port: count,
        remote_ip: addr, remote_port: count, transport: string, protocol: string,
        opnum: count, uuid: string, origin: string, connector_id: string);
    # Blackhole service accessed
    global dionaea_blackhole: event(timestamp: time, id: string, local_ip: addr, local_port: count, 
        remote_ip: addr, remote_port: count, transport: string, protocol: string, input: string, 
        length: count, origin: string, connector_id: string);

    # ## ACU EVENTS #
    global lattice_result: event(timestamp: time, attack: string);
    global acu_result: event(timestamp: time, attack: string);
    global tcp_event: event(rec: AlertInfo, discriminant: count);
		global lattice_event: event(rec: AlertInfo, discriminant: count);

    # ## MISC EVENTS ##

    # Conn::log_conn forwarding
    global log_conn: event(rec: Conn::Info);
}
