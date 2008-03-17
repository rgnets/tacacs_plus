require '../../lib/tacacs_plus.rb'
require 'yaml'

logger = Logger.new(STDOUT)
logger.level = Logger::DEBUG
client = TacacsPlus::Client.new(:key => 's0mek3y', :server => '127.0.0.1', :logger => logger, :dump_file => STDOUT)

client.authorize_command('ethan', 'configure terminal')

__END__


dialog = YAML.load_file("../dialogs/malformed_packets/authentication_minor_ver_not_supported.yaml")
client.script_play(dialog[:client_dialog])

client.login('dustin', 'password', true)

client.enable('dustin', 'enable', false)

client.pap_login('dustin', 'password')

client.chap_login('dustin', 'password', 'a', 'challenge')

client.change_enable_password('dustin','enable','new_password')

client.change_password('dustin','password2','new_password',true)

client.authorize_command('dustin', 'show version')

client.shell_settings('dustin')

client.account('dustin', ['task_id=1', 'timezone=cst'], :start => true)


__END__


