require '../../lib/tacacs_plus.rb'
require 'yaml'


if (ARGV[0])
    config = YAML.load_file(ARGV[0])
else
    config = YAML.load_file('../../tests/server_config.yaml')
end

logger = Logger.new(STDOUT)
config[:tacacs_daemon][:logger] = logger
config[:tacacs_daemon][:log_level] = 0
config[:tacacs_daemon][:dump_file] = STDOUT
tac_server = TacacsPlus::Server.new(config)

trap("INT"){ tac_server.log_client_connections!; tac_server.stop }
trap("TERM"){ tac_server.log_client_connections!; tac_server.stop }
trap("USR1") do
    logger = Logger.new(STDOUT)
    config[:tacacs_daemon][:logger] = logger
    config[:tacacs_daemon][:log_level] = 2
    tac_server.log_client_connections!
    tac_server.restart_with(config)
end
trap("USR2") do
    tac_server.log_client_connections!
    tac_server.restart
end


puts "### Starting with PID #{Process.pid} ###"
tac_server.start
