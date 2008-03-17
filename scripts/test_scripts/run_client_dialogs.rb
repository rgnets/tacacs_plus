require '../../lib/tacacs_plus.rb'
require 'yaml'

logger = Logger.new(STDOUT)
logger.level = Logger::DEBUG
client = TacacsPlus::Client.new(:key => 's0mek3y', :server => '127.0.0.1', :port => 49, :logger => logger )


if (ARGV.length == 0)
    Dir.chdir('../../dialogs')
    ["malformed_packets", "authentication", "authorization", "accounting", "cisco_captures"].each do |dir|
        print "\n\nPress 's' to skip, or any other key to continue with dialogs from grouping '#{dir}': "
        next if (STDIN.gets.chomp == 's')

        Dir.glob("#{dir}/*.yaml").each do |file|
            print "\n\n   ...press 's' to skip, or any other key to execute dialog '#{file}': "
            next if (STDIN.gets.chomp == 's')
            dialog = YAML.load_file(file)
            client.script_play(dialog[:client_dialog])
            print "\n\n\n"
        end
    end
else
    file = ARGV[0]
    dialog = YAML.load_file(file)
    client.script_play(dialog[:client_dialog])
end

__END__
