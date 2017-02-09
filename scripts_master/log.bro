module Beemaster;

export {
    redef LogAscii::empty_field = "EMPTY";
    redef enum Log::ID += {
      BALANCE_LOG,
      DIO_ACCESS_LOG,
      DIO_BLACKHOLE_LOG,
      DIO_DOWNLOAD_COMPLETE_LOG,
      DIO_DOWNLOAD_OFFER_LOG,
      DIO_FTP_LOG,
      DIO_LOGIN_LOG,
      DIO_MYSQL_COMMAND_LOG,
      DIO_SMB_BIND_LOG,
      DIO_SMB_REQUEST_LOG,
      ACU_ALERT_LOG,
      PORTSCAN_ALERT_LOG
      };

    type BalanceInfo: record {
      connector: string &log;
      slave: string &log;
    };

    type DioAccessInfo: record {
      ts: time &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_hostname: string &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      connector_id: string &log;
    };

    type DioBlackholeInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      input: string &log;
      length: count &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioDownloadCompleteInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      url: string &log;
      md5hash: string &log;
      filelocation: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioDownloadOfferInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      url: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioFtpInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      command: string &log;
      arguments: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioLoginInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      username: string &log;
      password: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioMysqlCommandInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      args: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioSmbBindInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      transfersyntax: string &log;
      uuid: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type DioSmbRequestInfo: record {
      ts: time &log;
      id: string &log;
      local_ip: addr &log;
      local_port: port &log;
      remote_ip: addr &log;
      remote_port: port &log;
      transport: string &log;
      protocol: string &log;
      opnum: count &log;
      uuid: string &log;
      origin: string &log;
      connector_id: string &log;
    };

    type AcuAlertInfo: record {
        ts: time &log;
        attack: string &log;
    };

    type PortscanAlertInfo: record {
        ts: time &log;
        attack: string &log;
        ips: vector of string &log;
    };
}

event bro_init() &priority=5 {
    Log::create_stream(BALANCE_LOG, [$columns=BalanceInfo, $path="balance"]);
    Log::create_stream(DIO_ACCESS_LOG, [$columns=DioAccessInfo, $path="dionaea_access"]);
    Log::create_stream(DIO_BLACKHOLE_LOG, [$columns=DioBlackholeInfo, $path="dionaea_blackhole"]);
    Log::create_stream(DIO_DOWNLOAD_COMPLETE_LOG, [$columns=DioDownloadCompleteInfo, $path="dionaea_download_complete"]);
    Log::create_stream(DIO_DOWNLOAD_OFFER_LOG, [$columns=DioDownloadOfferInfo, $path="dionaea_download_offer"]);
    Log::create_stream(DIO_FTP_LOG, [$columns=DioFtpInfo, $path="dionaea_ftp"]);
    Log::create_stream(DIO_LOGIN_LOG, [$columns=DioLoginInfo, $path="dionaea_login"]);
    Log::create_stream(DIO_MYSQL_COMMAND_LOG, [$columns=DioMysqlCommandInfo, $path="dionaea_mysql_command"]);
    Log::create_stream(DIO_SMB_BIND_LOG, [$columns=DioSmbBindInfo, $path="dionaea_smb_bind"]);
    Log::create_stream(DIO_SMB_REQUEST_LOG, [$columns=DioSmbRequestInfo, $path="dionaea_smb_request"]);
    Log::create_stream(ACU_ALERT_LOG, [$columns=AcuAlertInfo, $path="acu_alert"]);
    Log::create_stream(PORTSCAN_ALERT_LOG, [$columns=PortscanAlertInfo, $path="portscan_alert"]);
}
