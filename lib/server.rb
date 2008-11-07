require 'logger'
require File.join(File.dirname(__FILE__), 'server_config_elements.rb')
require File.join(File.dirname(__FILE__), 'client_connection.rb')

module TacacsPlus

#A class for creating TACACS+ servers.
#
#The Server class uses a number of concepts, which
#are defined as:
#* Object Groups - Come in 2 flavors; Network and Shell Command. Object Groups provide
#  a mechanism for grouping like objects together. Network Object Groups contain IP addresses, while
#  Shell Command Object Groups contain shell commands.
#* ACLs - Define access controls for various tasks by permitting or denying based on source IP of the clients. They have an
#  implicit deny at the end.
#* Authorization AVPairs - Define the shell settings a user is granted upon login to specific devices.
#* Command Authorization Profiles - Define the shell commands a user may run, and from which devices they may run them.
#  They have an implicit deny at the end.
#* Command Authorization Whitelist - Authorization for any command listed here will always pass regardless
#  of the user requesting the authorization. This essentially bypasses normal authorization proceedures, thus it is useful for basic
#  commands such as 'login' or 'exit' which should always be available to all users (very useful for situations where you find
#  yourself locked out of a device due to AAA Authentication errors)
#* User Groups - Allows various settings to be granted to a collection of users.
#
#A number of options may be passed during the initialization of a server. These options are as follows:
#
#* :acls - Contains a Hash of Arrays. The key of the Hash indicates the acl name,
#  and the value is an Array of Hashes with the keys:
#  * :ip -  IP address (optional if :network_object_group provided)
#  * :network_object_group - indicates a Network Object Group name to be used in the acl (optional if :ip provided)
#  * :permission - should be either 'permit' or 'deny' (required)
#  * :wildcard_mask - a special mask used for advanced IP pattern matching. Wildcard masks are always
#    in bit-flipped format. For example the range 192.168.1.0/24 would be indicated
#    with :ip => 192.168.1.0, :wildcard_mask => 0.0.0.255.(optional. defaults to 0.0.0.0)
#
#* :author_avpairs - Contains a Hash of Arrays. The key of the Hash
#  indicates the profile name, and the value is an Array of Hashes with keys:
#  * :acl - the name of an ACL to be used for issuing shell settings on a per-device basis (optional)
#  * :avpairs - an array of attribute-value pairs in the form 'attribute=value' or 'attribute*value' (required. see tac-rfc.1.78.txt for complete list of avpairs)
#  * :service - a String indicating one of the standard Service AVPairs (shell, raccess, ppp, etc...) (required)
#
#* :command_authorization_profiles - Contains a Hash of Arrays. The key of the Hash
#  indicates the profile name, and the value is an Array of Hashes with the keys:
#  * :acl - the name of an ACL to be used for authorizting shell commands on a per-device basis. (optional)
#  * :command - an individial shell command (optional if :shell_command_object_group provided)
#  * :shell_command_object_group - indicates the name of a Shell Command Object Group (optional if :command provided)
#
#* :command_authorization_whitelist - Array of Hashes with the keys:
#  * :acl - the name of an ACL to be used for authorizting shell commands on a per-device basis.
#  * :command - an individial shell command (optional if :shell_command_object_group provided)
#  * :shell_command_object_group - indicates the name of a Shell Command Object Group (optional if :command provided)
#
#* :network_object_groups - Contains a Hash of Arrays. The key of the Hash
#  indicates the object group name, and the value is an Array of network blocks in either 
#  extended (x.x.x.x y.y.y.y) or cidr (x.x.x.x/y) format
#
#* :shell_command_object_groups - Contains a Hash of Arrays. The key of the Hash
#  indicates the object group name, and the value is an Array of shell commands.
#
#* :tacacs_daemon - Contains a Hash with the keys:
#  * :default_policy - defines how to handle users with no login/enable acls or no command authorization profile. must be :permit or :deny. defaults to :deny.
#  * :delimiter - the delmitation character used in logging. defaults to \t.
#  * :disabled_prompt - message to display to user if their account is disabled
#  * :dump_file - IO object for dumping output of packet captures.
#  * :ip - the IP on which to bind the daemon.
#  * :key - the encryption key to use for client/server communication.
#  * :log_accounting - if set false, do not log accounting requests
#  * :log_authentication - if set false, do not log authentication requests
#  * :log_authorization - if set false, do not log authorization requests
#  * :log_level - one of the standard Logger levels (0-4)
#  * :logger - Logger object for dumping log entries
#  * :login_prompt - a custom definable login prompt.
#  * :max_clients - the max concurrent client connections allowed.
#  * :name - the name of this daemon (if present, included in logs as field 'tacacs_daemon')
#  * :password_expired_prompt - message to display to user if their password is expired
#  * :password_prompt - a custom definable password prompt.
#  * :port - the TCP port on which to bind the daemon.
#  * :sock_timeout - the time in seconds in which clients may be idle before the connection times out.
#  * :testing - enable testing mode if set True. testing mode allows for unencrypted traffic to be accepted.
#
#* :user_groups - Contains a Hash of Hashes. The key indicates the group name, and the value
#  is a Hash with the keys:
#  * :command_authorization_profile - the name of a command authorization profile to use for this group. 
#  * :enable_acl - the name of an ACL specifying devices on which users may request enable.
#  * :login_acl - the name of an ACL specifying devices on which users may login.
#  * :author_avpair - the name of a shell profile for the group.
#
#* :users - Contains a Hash of Hashes. The key indicates the username, and the value
#  is a Hash with the keys:
#  * :command_authorization_profile - the name of a command authorization profile to use for this user.
#  * :disabled - set True if user account is disabled
#  * :enable_password - the user enable password.
#  * :enable_acl - the name of an ACL specifying devices on which the user may request enable.
#  * :enable_password_expires_on - date on which the enable password is considered expired (eg. '2008-01-01'). :password_lifespan must be > 0 for this option to take effect.
#  * :enable_password_lifespan - Integer representing the number of days enable password is considered valid (0 = forever)
#  * :encryption - the encryptions scheme of the passwords ('clear' or 'sha1'). This field is required if any passwords are provided.
#  * :login_acl - the name of an ACL specifying devices on which the user may login.
#  * :login_password - the login password.
#  * :login_password_expires_on - date on which the login password is considered expired (eg. '2008-01-01'). :password_lifespan must be > 0 for this option to take effect.
#  * :login_password_lifespan - Integer representing the number of days password is considered valid (0 = forever)
#  * :salt - the salt value used as part of an sha1 hashed password.
#  * :author_avpair - the name of a shell profile for the group.
#  * :user_group - the name of a user group to which this user belongs.
#
#A note on password expiry: The user options x_password_expires_on and x_password_lifespan are used to enforce password changes
#by users. For example, if you want to force users to change their password every 30 days then you would set the x_password_lifespan
#field to 30. If you do not want to force password changes ever, then you would leave the field blank (or set 0). The x_password_expires_on
#field should never need to be specified as it is set automatically when the user changes their password. 
#
class Server


#==============================================================================#
# initialize()
#==============================================================================#

#===Synopsis
#Create a new TacacsPlus::Server object. See explaination above.
#
#===Usage
#
#  shell_command_object_groups = {'show commands' => ['show version', 'show running-configuration']}
#
#  network_object_groups = {'datacenter1' => ['10.1.0.0/16', '10.3.0.0/16'] }
#
#  acls = {'deny local' => [{:permission => 'deny', :ip => '127.0.0.1', :wildcard_mask => '0.0.255.255'},
#                            {:permission => 'permit', :ip => 'any'} ],
#           'permit dc' => [{:permission => 'permit', :network_object_group => 'datacenter1'}],
#           'permit all' => [{:permission => 'permit', :ip => 'any'}],
#           'permit local' => [{:permission => 'permit', :ip => '127.0.0.1', :wildcard_mask => '0.0.255.255'} ] }
#
#  command_authorization_profiles = {'profile1' => [{:acl => 'permit all', :shell_command_object_group => 'show commands'},
#                                                   {:acl => 'permit dc', :command => 'configure terminal'} ] }
#  command_authorization_whitelist = ['enable', 'exit']
#
#  author_avpairs = {'shell profile 1' => [ {:acl => 'permit dc', :avpairs => ['idletime=5','priv_lvl=1'] },
#                                           {:acl => 'permit local', :avpairs => ['priv_lvl=15'] } ],
#                    'shell profile 2' => [ {:acl => 'permit dc', :avpairs => ['idletime=5','priv_lvl=1'] }] }
#
#  user_groups = {'group1' => {enable_acl => 'permit local'},
#                 'group2' => {:command_authorization_profile => 'profile1'} }
#
#  users = { 'dustin' => {:password => 'password', :encryption => 'clear', :command_authorization_profile => 'profile1',
#                         :enable => 'enable', :author_avpair => 'shell profile 1'},
#            'tom' => {:password => 'password', :encryption => 'clear', :user_group => 'group1'} }
#
#  tacacs_daemon = {:key => 's0mek3y'}
#
#  config = {:shell_command_object_groups => shell_command_object_groups, :network_object_groups => network_object_groups,
#            :acls => acls, :command_authorization_profiles => command_authorization_profiles,
#            :author_avpairs => author_avpairs, :user_groups => user_groups, :users => users, :tacacs_daemon => tacacs_daemon }
#
# server = TacacsPlus::Server.new(config)
#
#
#===Notes
#See the file tacacs_plus_server.tar.gz for a sample server daemon script.
#
#
    def initialize(options)
        process_options(options)
    end

#==============================================================================#
# configuration()
#==============================================================================#

# Return the current configuration as a Hash.
#
    def configuration()
        cfg = {:shell_command_object_groups => {}, :network_object_groups => {}, :acls => {}, :command_authorization_profiles => {},
               :command_authorization_whitelist => [], :author_avpairs => {}, :user_groups => {}, :users => {}}
        cfg[:tacacs_daemon] = @tacacs_daemon.configuration
        @tacacs_daemon.shell_command_object_groups.each {|x| cfg[:shell_command_object_groups][x.name] = x.configuration }
        @tacacs_daemon.network_object_groups.each {|x| cfg[:network_object_groups][x.name] = x.configuration }
        @tacacs_daemon.acls.each {|x| cfg[:acls][x.name] = x.configuration }
        @tacacs_daemon.command_authorization_profiles.each {|x| cfg[:command_authorization_profiles][x.name] = x.configuration }
        @tacacs_daemon.command_authorization_whitelist.each {|x| cfg[:command_authorization_whitelist].push(x.configuration) }
        @tacacs_daemon.author_avpairs.each {|x| cfg[:author_avpairs][x.name] = x.configuration }
        @tacacs_daemon.user_groups.each {|x| cfg[:user_groups][x.name] = x.configuration }
        @tacacs_daemon.users.each {|x| cfg[:users][x.username] = x.configuration }
        return(cfg)
    end

#==============================================================================#
# restart()
#==============================================================================#

# Restart the server.
#
    def restart()
        stop("TACACS+ server restart requested.") if (@listener.alive?)
        start_server
        return(nil)
    end

#==============================================================================#
# restart_logger()
#==============================================================================#

# If :logger option is the name of a file, then re-initialize the logger
#
    def restart_logger()
        if (@listener.alive?)
            @listener.raise( LoggerInit.new )
            return(true)
        else
            return(false)
        end
    end

#==============================================================================#
# restart_with()
#==============================================================================#

# Restart the server with a new configuration. Options are the same as with #new.
#
    def restart_with(options)
        begin
            process_options(options)
            stop("TACACS+ server restart requested (updated configuration).") if (@listener.alive?)
            start_server
        rescue Exception => error
            STDERR.puts("\n\n#### #{Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")} - RESTART FAILED. CAUGHT EXCEPTION ON TacacsPlus::Server#restart_with ####\n #{error}.\n\n#{error.backtrace.join("\n")}")
        end
        return(nil)
    end

#==============================================================================#
# start()
#==============================================================================#

# Start the TACACS Plus Server.
#
    def start()
        @tacacs_daemon.log(:info,['msg_type=TacacsPlus::Server', 
                           "message=Starting TACACS+ server with pid #{Process.pid}."]) if (start_server)
        return(nil)
    end

#==============================================================================#
# stop()
#==============================================================================#

# Stop the TACACS Plus Server. Return True on success, or False otherwise.
#
    def stop(msg="TACACS+ server shutdown requested.")
        if (@listener.alive?)
            @listener.raise( StopServer.new(msg) )
            @server.close if (!@server.closed?)
            return(true)
        else
            return(false)
        end
    end

#==============================================================================#
# test()
#==============================================================================#

# Used for offline server testing.
#
    def test(socket,ip='127.0.0.1')  #:nodoc:
        # open dump_file and logger if they are Strings
        peeraddr = NetAddr::CIDR.create(ip)
        @tacacs_daemon.dump_file = nil
        @tacacs_daemon.log(:info,['msg_type=TacacsPlus::Server', 'message=Starting TACACS+ server (Offline Testing Mode).'])
        client_connection = ClientConnection.new(@tacacs_daemon, socket, peeraddr)
        client_connection.process!
        return(nil)
    end




private

#==============================================================================#
# init_logger()
#==============================================================================#

# start the logger
#

    def init_logger!
        if (@tacacs_daemon.log_file)
            begin
                @tacacs_daemon.logger = TacacsPlus::ServerLogger.new(@tacacs_daemon.log_file)
                @tacacs_daemon.logger.delimiter = @tacacs_daemon.delimiter
            rescue Exception => error
                raise "Error opening logger #{@tacacs_daemon.log_file}: #{error}"
            end
        end

        @tacacs_daemon.logger.level = @tacacs_daemon.logger_level
    end



#==============================================================================#
# process_options()
#==============================================================================#

# process config for server
#
    def process_options(options)
        known_args = [:acls, :author_avpairs, :command_authorization_profiles, :command_authorization_whitelist, :network_object_groups,
                      :shell_command_object_groups, :tacacs_daemon, :user_groups, :users]

        # validate options
        if (!options.kind_of?(Hash))
            raise ArgumentError, "Expected Hash, but #{options.class} provided."
        end
        TacacsPlus.validate_args(options.keys,known_args)

         # validate tacacs_daemon
        if (options.has_key?(:tacacs_daemon))
            if (!options[:tacacs_daemon].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :tacacs_daemon, but #{options[:tacacs_daemon].class} provided."
            end
            @tacacs_daemon = TacacsDaemon.new(options[:tacacs_daemon])
        else
            raise ArgumentError, "Missing argument :tacacs_daemon."
        end

          # are object groups provided?
        if (options.has_key?(:network_object_groups))
            if (!options[:network_object_groups].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :network_object_groups, but #{options[:network_object_groups].class} provided."
            end

            list = []
            options[:network_object_groups].each_pair {|name,entries| list.push( NetworkObjectGroup.new(name,entries) ) }
            @tacacs_daemon.network_object_groups = list
        end

         # are shell command groups provided?
        if (options.has_key?(:shell_command_object_groups))
            if (!options[:shell_command_object_groups].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :shell_command_object_groups, but #{options[:shell_command_object_groups].class} provided."
            end

            list = []
            options[:shell_command_object_groups].each_pair {|name,entries| list.push( ShellCommandObjectGroup.new(name,entries) ) }
            @tacacs_daemon.shell_command_object_groups = list
        end

         # are acls provided?
        if (options.has_key?(:acls))
            if (!options[:acls].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :acls, but #{options[:acls].class} provided."
            end

            list = []
            options[:acls].each_pair {|name,entries| list.push( Acl.new(@tacacs_daemon,name,entries) ) }
            @tacacs_daemon.acls = list
        end

         # are shell profiles provided?
        if (options.has_key?(:author_avpairs))
            if (!options[:author_avpairs].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :author_avpairs, but #{options[:author_avpairs].class} provided."
            end

            list = []
            options[:author_avpairs].each_pair {|name,entries| list.push( AuthorAVPair.new(@tacacs_daemon,name,entries) ) }
            @tacacs_daemon.author_avpairs = list
        end

         # are command authorization profiles provided?
        if (options.has_key?(:command_authorization_profiles))
            if (!options[:command_authorization_profiles].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :command_authorization_profiles, but #{options[:command_authorization_profiles].class} provided."
            end

            list = []
            options[:command_authorization_profiles].each_pair {|name,entries| list.push( CommandAuthorizationProfile.new(@tacacs_daemon,name,entries) ) }
            @tacacs_daemon.command_authorization_profiles = list
        end

         # is command authorization whitelist provided?
        if (options.has_key?(:command_authorization_whitelist))
            if (!options[:command_authorization_whitelist].kind_of?(Array))
                raise ArgumentError, "Expected Array for argument :command_authorization_whitelist, but #{options[:command_authorization_whitelist].class} provided."
            end

            list = []
            options[:command_authorization_whitelist].each {|entry| list.push( CommandAuthorizationWhitelistEntry.new(@tacacs_daemon,entry) ) }
            @tacacs_daemon.command_authorization_whitelist = list
        end

        # are user groups provided?
        if (options.has_key?(:user_groups))
            if (!options[:user_groups].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :user_groups, but #{options[:user_groups].class} provided."
            end

            list = []
            options[:user_groups].each_pair {|name,grp_opts| list.push( UserGroup.new(@tacacs_daemon,name,grp_opts) ) }
            @tacacs_daemon.user_groups = list
        end

        # validate users
        if (options.has_key?(:users))
            if (!options[:users].kind_of?(Hash))
                raise ArgumentError, "Expected Hash for argument :users, but #{options[:users].class} provided."
            end

            list = []
            options[:users].each_pair {|username,user_opts| list.push( TacacsUser.new(@tacacs_daemon,username,user_opts) ) }
            @tacacs_daemon.users = list
        end

    end

#==============================================================================#
# start_server()
#==============================================================================#

# Start the TACACS Plus Server
#
    def start_server()
        # open dump_file and logger if they are Strings
        if (@dump_file.kind_of?(String))
            filename = @dump_file
            begin
                @dump_file = File.open(filename, 'w')
            rescue Exception => error
                raise "Error opening dump_file #{filename}: #{error}"
            end
        end

        init_logger!
        @server = TCPServer.new(@tacacs_daemon.ip, @tacacs_daemon.port)
        @clients = ThreadGroup.new
        BasicSocket.do_not_reverse_lookup = true
        Thread.abort_on_exception = true

        @listener = Thread.new do
            while(true)
                begin
                    thread = Thread.new(@server.accept) do |client_socket|
                        peeraddr = nil
                        begin
                            peeraddr = NetAddr::CIDR.create( client_socket.peeraddr[3] )
                        rescue Exception => error
                            @tacacs_daemon.log(:debug,['msg_type=TacacsPlus::Server', "message=Could not obtain client IP. Terminating connection."])
                            client_socket.close if (!client_socket.closed?)
                        end

                        if (peeraddr)
                            if (@clients.list.length >= @tacacs_daemon.max_clients)
                                @tacacs_daemon.log(:warn,['msg_type=TacacsPlus::Server', 'message=Maximum connection limit reached. Rejecting new connection.'],nil,peeraddr)
                                client_socket.close
                            else
                                client_connection = ClientConnection.new(@tacacs_daemon, client_socket, peeraddr)
                                begin
                                    client_connection.process!
                                rescue Exception => err
                                    STDERR.puts("\n\n#### #{Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")} - CAUGHT EXCEPTION WHILE PROCESSING CLIENT REQUEST ####\n #{err}.\n\n#{err.backtrace.join("\n")}")
                                    client_socket.close if (!client_socket.closed?)
                                end
                            end
                        end
                    end
                    @clients.add(thread)

                rescue LoggerInit
                    init_logger!
                rescue StopServer => msg
                    @tacacs_daemon.log(:info,['msg_type=TacacsPlus::Server', "message=#{msg}"])
                    Thread.exit
                rescue Exception => err
                    STDERR.puts("\n\n#### #{Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")} - CAUGHT EXCEPTION ON NEW REQUEST ####\n #{err}.\n\n#{err.backtrace.join("\n")}")
                end
            end
        end
        @listener.join

        begin
            @server.close if (!@server.closed?)
            @dump_file.close if (@dump_file && !@dump_file.closed?)
            @tacacs_daemon.logger.close if (@tacacs_daemon.logger && !@tacacs_daemon.logger.closed?)
        rescue Exception
        end

        return(true)
    end


end # class Server


end # module TacacsPlus

__END__
