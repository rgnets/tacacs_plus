require 'timeout'

module TacacsPlus

# A class for creating TACACS+ clients.
class Client

attr_reader :key, :logger, :dump_file, :port, :server, :session_id, :sock_timeout, :testing

# MIXINS
    include TacacsPlus::TacacsSocket

#==============================================================================#
# initialize()
#==============================================================================#

#===Synopsis
#Create a new TacacsPlus::Client object.
#
#===Usage
# TacacsPlus::Client.new(:key => 's0mek3y', :server => '127.0.0.1')
#
#===Arguments
#Hash with the following fields:
# :key => [String] -- Encryption key
# :logger => [Logger] -- Logger object for logging output
# :log_level - one of the standard Logger levels (0-4)
# :dump_file => [IO] -- record all server I/O as YAML to provided IO object.
# :port => [Integer] -- TCP port of server TACACS+ daemon
# :server => [String] -- ip/hostname of TACACS+ server.
# :session_id => [Integer] -- session id which client should use. will be random by default.
# :sock_timeout => [Integer] -- timeout for client connections to server
# :testing => [TrueClass|FalseClass] -- Enable testing mode if set True. Testing mode allows for unencrypted traffic to be accepted.
#
    def initialize(options)
        @logger = nil
        @socket = nil
        @port = 49
        @key = nil
        @dump_file = nil
        @sock_timeout = 2
        @session_id = nil


        if (!options.kind_of?(Hash))
            raise ArgumentError, "Expected Hash, but #{options.class} provided."
        end

        if (options.has_key?(:server))
            @server = options[:server]
            if (!@server.kind_of?(String))
                raise ArgumentError, "Expected String for :server, but #{@server.class} provided."
            end
        else
            raise ArgumentError, "Missing argument :server."
        end

        if (options.has_key?(:port))
            @port = options[:port]
            if (!@port.kind_of?(Integer))
                raise ArgumentError, "Expected Integer for :port, but #{@port.class} provided."
            end
            if (@port >= 2**16)
                raise ArgumentError, "#{@port} is not a valid TCP port."
            end
        end

        if (options.has_key?(:key))
            @key = options[:key]
            if (!@key.kind_of?(String))
                raise ArgumentError, "Expected String for :key, but #{@key.class} provided."
            end
        end

        if (options.has_key?(:logger))
            if (options[:logger].kind_of?(String))
                begin
                    @logger = Logger.new(options[:logger])
                rescue Exception => error
                    raise ArgumentError, "Error with argument :logger: #{error}"
                end
            else
                @logger = options[:logger]
            end
        end

        if (options.has_key?(:log_level))
            if ( options[:log_level].kind_of?(Integer) )
                if ( (0..4).member?(options[:log_level]) )
                    @logger.level = options[:log_level] if @logger
                else
                    raise ArgumentError, "Argument :log_level should be between 0 and 4, but was #{options[:log_level]}."
                end
            else
                raise ArgumentError, "Expected Integer for argument :log_level, but #{options[:log_level].class} provided."
            end
        end

        if (options.has_key?(:dump_file))
            if (options[:dump_file].kind_of?(String))
                begin
                    @dump_file = File.open(options[:dump_file], 'w')
                rescue Exception => error
                    raise ArgumentError, "Error with argument :dump_file: #{error}"
                end
            elsif (options[:dump_file].kind_of?(IO))
                @dump_file = options[:dump_file]
            else
                raise ArgumentError, "Expected IO for :dump_file, but #{options[:dump_file].class} provided."
            end
        end

        if (options.has_key?(:session_id))
            @session_id = options[:session_id]
            if (!@session_id.kind_of?(Integer))
                raise ArgumentError, "Expected Integer for :session_id, but #{@session_id.class} provided."
            end
        end

        if (options.has_key?(:testing))
            @testing = options[:testing]
            raise ArgumentError, "Expected True or False for :testing, " +
                                 "but was #{@testing.class}" if (!@testing.kind_of?(TrueClass) && !@testing.kind_of?(FalseClass))
        end

        if (options.has_key?(:sock_timeout))
            @sock_timeout = options[:sock_timeout]
            if (!@sock_timeout.kind_of?(Integer))
                raise ArgumentError, "Expected Integer for :sock_timeout, but #{@sock_timeout.class} provided."
            end
        end

    end

#==============================================================================#
# attr_writers()
#==============================================================================#

#:key, :logger, :dump_file, :port, :server, :session_id, :sock_timeout, :testing
    def key=(key)
        if (!key.kind_of?(String))
            raise ArgumentError, "Expected String, but #{key.class} provided."
        end
        @key = key
    end

    def logger=(logger)
        @logger = logger
    end

    def dump_file=(dump_file)
        if (!dump_file.kind_of?(IO))
            raise ArgumentError, "Expected IO, but #{dump_file.class} provided."
        end
        @dump_file = dump_file
    end

    def port=(port)
        if (!port.kind_of?(Integer))
            raise ArgumentError, "Expected Integer, but #{port.class} provided."
        end
        if (port >= 2**16)
            raise ArgumentError, "#{port} is not a valid TCP port."
        end
        @port = port
    end

    def server=(server)
        if (!server.kind_of?(String))
            raise ArgumentError, "Expected String, but #{server.class} provided."
        end
        @server = server
    end

    def session_id=(session_id)
        if (!session_id.kind_of?(Integer))
            raise ArgumentError, "Expected Integer, but #{session_id.class} provided."
        end
        @session_id = session_id
    end

    def sock_timeout=(sock_timeout)
        if (!sock_timeout.kind_of?(Integer))
            raise ArgumentError, "Expected Integer, but #{sock_timeout.class} provided."
        end
        @sock_timeout = sock_timeout
    end

    def testing=(testing)
        if (!testing.kind_of?(TrueClass) && !testing.kind_of?(FalseClass))
            raise ArgumentError, "Expected True or False for :testing, but was #{testing.class}"
        end
        @testing = testing
    end

    # Used for unit testing only
    def socket #:nodoc:
        return @socket
    end

    def socket=(socket) #:nodoc:
        @socket = socket
    end

#==============================================================================#
# account()
#==============================================================================#

#===Synopsis
# Send an accounting request to a server.
#
#===Usage
# client.account('user1', ['task_id=1', 'timezone=cst'], :start => true)
#
#===Arguments
# * username => [String] --  Mandatory
# * args => [Array] -- list of avpairs. See tac-rfc.1.78.txt for list of accounting avpairs.
# * flags => [Hash] -- set any of the following keys to true to set the appropriate flags: :start, :stop, :watchdog
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def account(username,args,flags=nil)
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!args.kind_of?(Array))
                raise ArgumentError, "Expected Array for args, but #{args.class} provided."
        end

        # validate args
         args.each {|arg| TacacsPlus.validate_avpair(arg)}

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AccountingRequest.new
        body.priv_lvl = 1
        body.authen_type_ascii!
        body.args = args
        body.user = username

        if (!flags.kind_of?(Hash))
                raise ArgumentError, "Expected Hash for flags, but #{flags.class} provided."
        else
            body.flag_start! if (flags.has_key?(:start) && flags[:start] == true)
            body.flag_stop! if (flags.has_key?(:stop) && flags[:stop] == true)
            body.flag_watchdog! if (flags.has_key?(:watchdog) && flags[:watchdog] == true)
        end

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :accounting
        session.args = args

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# authorization_avpairs()
#==============================================================================#

#===Synopsis
# Request AVPairs representing shell or other settings from a TACACS+ server.
#
#===Usage
# client.authorization_avpairs('user1')
# client.authorization_avpairs('user1', 'raccess')
#
#
#===Arguments
# * username => [String] --  Mandatory
# * service => [String] -- Optional
#
#===Returns
#Hash with the following fields:
# :args => [Array] -- list of avpairs returned by the server
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :pass_type => [:add|:repl] -- indicates whether server returned a pass_add or pass_repl message
# :server_msg  => [String] -- message to be presented to user
#
    def authorization_avpairs(username, service='shell')
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!service.kind_of?(String))
                raise ArgumentError, "Expected String for service, but #{service.class} provided."
        end

        # set args
        if (service == 'shell')
            args = ['service=shell', 'cmd=']
        else
            args = ["service=#{service}"]
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthorizationRequest.new
        body.priv_lvl = 1
        body.authen_type_ascii!
        body.args = args
        body.user = username

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authorization
        session.args = args

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# authorize_command()
#==============================================================================#

#===Synopsis
# Perform shell command authorization on a TACACS+ server.
#
#===Usage
# client.authorize_command('user1', 'show running-configuration <cr>')
#
#
#===Arguments
# * username => [String] --  Mandatory
# * command => [String] -- Mandatory
#
#===Returns
#Hash with the following fields:
# :args => [Array] -- list of avpairs returned by the server
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :pass_type => [:add|:repl] -- indicates whether server returned a pass_add or pass_repl message
# :server_msg  => [String] -- message to be presented to user
#
    def authorize_command(username,command)
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!command.kind_of?(String))
                raise ArgumentError, "Expected String for command, but #{command.class} provided."
        end

        # set args
        args = ['service=shell']
        cmd_args = command.split(' ')
        cmd = "cmd=#{cmd_args.shift}"
        begin
            TacacsPlus.validate_avpair(cmd)
            args.push(cmd)
            cmd_args.each do |cmd_arg|
                cmd_arg = 'cmd-arg=' + cmd_arg
                TacacsPlus.validate_avpair(cmd_arg)
                args.push(cmd_arg)
            end
        rescue => error
            raise ArgumentError, "String provided as shell command was improperly formed and raised " +
                                 "the following error: #{error}"
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthorizationRequest.new
        body.priv_lvl = 1
        body.authen_type_ascii!
        body.args = args
        body.user = username

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authorization
        session.args = args

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# change_enable_password()
#==============================================================================#

#===Synopsis
# Perform a user enable password change on a TACACS+ server.
#
#===Usage
# client.change_enable_password('user1', 'password', 'new_password')
#
#===Arguments
# * username => [String] --  Mandatory
# * password => [String] --  Mandatory
# * new_password => [String] --  Mandatory
# * quick => [TrueClass|FalseClass] -- if true, then send username as part of Authentication Start -- Optional
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def change_enable_password(username,password,new_password,quick=true)
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!password.kind_of?(String))
                raise ArgumentError, "Expected String for password, but #{password.class} provided."
        end

        if (!new_password.kind_of?(String))
                raise ArgumentError, "Expected String for new_password, but #{new_password.class} provided."
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthenticationStart.new
        body.action_chpass!
        body.authen_type_ascii!
        body.service_enable!
        body.priv_lvl = 1
        body.user = username if (quick)

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authentication
        session.getuser = username
        session.getpass = new_password
        session.getdata = password

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# change_password()
#==============================================================================#

#===Synopsis
# Perform a user login password change on a TACACS+ server.
#
#===Usage
# client.change_password('user1', 'password', 'new_password')
#
#===Arguments
# * username => [String] --  Mandatory
# * password => [String] --  Mandatory
# * new_password => [String] --  Mandatory
# * quick => [TrueClass|FalseClass] -- if true, then send username as part of Authentication Start -- Optional
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def change_password(username,password,new_password,quick=true)
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!password.kind_of?(String))
                raise ArgumentError, "Expected String for password, but #{password.class} provided."
        end

        if (!new_password.kind_of?(String))
                raise ArgumentError, "Expected String for new_password, but #{new_password.class} provided."
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthenticationStart.new
        body.action_chpass!
        body.authen_type_ascii!
        body.priv_lvl = 1
        body.user = username if (quick)

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authentication
        session.getuser = username
        session.getpass = new_password
        session.getdata = password

    # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# chap_login()
#==============================================================================#

#===Synopsis
# Perform ascii login authentication on a TACACS+ server.
#
#===Usage
# client.chap_login('user1', 'password', 'A', 'abcd')
#
#===Arguments
# * username => [String] --  Mandatory
# * password => [String] --  Mandatory
# * ppp_id =>  [String] --  Mandatory, 1 Byte
# * challenge => [String] --  Mandatory
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def chap_login(username,password,ppp_id,challenge)
        if (!username.kind_of?(String))
            raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!password.kind_of?(String))
            raise ArgumentError, "Expected String for password, but #{password.class} provided."
        end

        if (!ppp_id.kind_of?(String))
            raise ArgumentError, "Expected String for ppp_id, but #{ppp_id.class} provided."
        elsif (ppp_id.length != 1)
            raise ArgumentError, "Expected 1-byte String for ppp_id, but was #{ppp_id.length} bytes."
        end

        if (!challenge.kind_of?(String))
            raise ArgumentError, "Expected String for challenge, but #{challenge.class} provided."
        elsif (challenge.length > 255)
            raise ArgumentError, "Challenge may not be more then 255 bytes."
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        header.minor_version_one!
        body = TacacsPlus::AuthenticationStart.new
        body.action_login!
        body.authen_type_chap!
        body.priv_lvl = 1
        body.user = username
        # data should contain contat of ppp_id, challenge, and response
        body.data = ppp_id + challenge + Digest::MD5.digest(ppp_id + password + challenge)

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authentication
        session.getuser = username
        session.getpass = password

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# enable()
#==============================================================================#

#===Synopsis
# Perform enable service authentication on a TACACS+ server.
#
#===Usage
# client.enable('user1', 'password')
#
#===Arguments
# * username => [String] --  Mandatory
# * password => [String] --  Mandatory
# * quick => [TrueClass|FalseClass] -- if false, then dont send username as part of Authentication Start -- Optional
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def enable(username,password,quick=true)

        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!password.kind_of?(String))
                raise ArgumentError, "Expected String for password, but #{password.class} provided."
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthenticationStart.new
        body.action_login!
        body.priv_lvl = 15
        body.service_enable!
        body.user = username if (quick)

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authentication
        session.getuser = username
        session.getpass = password

        # process server dialog
        enable_attempt = process_response(session, socket)

        return(enable_attempt)
    end

#==============================================================================#
# login()
#==============================================================================#

#===Synopsis
# Perform ascii login authentication on a TACACS+ server.
#
#===Usage
# client.login('user1', 'password')
#
#===Arguments
# * username => [String] --  Mandatory
# * password => [String] --  Mandatory
# * quick => [TrueClass|FalseClass] -- if true, then send username as part of Authentication Start -- Optional
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def login(username,password,quick=false)
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!password.kind_of?(String))
                raise ArgumentError, "Expected String for password, but #{password.class} provided."
        end


        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthenticationStart.new
        body.action_login!
        body.authen_type_ascii!
        body.priv_lvl = 1
        body.user = username if (quick)

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authentication
        session.getuser = username
        session.getpass = password

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# pap_login()
#==============================================================================#

#===Synopsis
# Perform ascii login authentication on a TACACS+ server.
#
#===Usage
# client.pap_login('user1', 'password')
#
#===Arguments
# * username => [String] --  Mandatory
# * password => [String] --  Mandatory
#
#===Returns
#Hash with the following fields:
# :data => [String] -- message to be presented to administrator
# :pass  => [true|false] -- true if request successful
# :server_msg  => [String] -- message to be presented to user
#
    def pap_login(username,password)
        if (!username.kind_of?(String))
                raise ArgumentError, "Expected String for username, but #{username.class} provided."
        end

        if (!password.kind_of?(String))
                raise ArgumentError, "Expected String for password, but #{password.class} provided."
        end

        # open a socket to the server
        socket = open_socket()

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        header.minor_version_one!
        body = TacacsPlus::AuthenticationStart.new
        body.action_login!
        body.authen_type_pap!
        body.priv_lvl = 1
        body.user = username
        body.data = password

        session = ClientSession.new()
        session.request = PacketStruct.new(header,body)
        session.type = :authentication
        session.getuser = username
        session.getpass = password

        # process server dialog
        attempt = process_response(session, socket)

        return(attempt)
    end

#==============================================================================#
# script_play()
#==============================================================================#

#===Synopsis
# Send a series of pre-defined packets to a TACACS+ server. This is useful
# for testing a server's response to malformed TACACS+ requests.
#
#===Usage
# packet1 = TacacsPlus::PacketStruct.new(TacacsPlus::TacacsHeader.new, AuthenticationStart.new)
# packet1.header.type_authentication!
# packet2 = TacacsPlus::PacketStruct.new(TacacsPlus::TacacsHeader.new, TacacsPlus::AuthenticationContinue.new)
# packet2.header.type_authorization! # see how server reacts to 'type' field set incorrectly
#
# client.script_play( [packet1,packet2] )
#
#===Arguments
# * script => Array of PacketStruct objects
#
#===Returns
# * nil
#
    def script_play(script)
        entry_num = 1
        script.each do |entry|
            raise "PacketStruct required, but entry number #{entry_num} was of type #{entry.class}." if (!entry.kind_of?(PacketStruct))
            raise "TacacsHeader required, but #header portion of entry number #{entry_num} was of type #{entry.header.class}." if (!entry.header.kind_of?(TacacsPlus::TacacsHeader))
            raise "TacacsBody required, but #body portion of entry number #{entry_num} was of type #{entry.body.class}." if (!entry.body.kind_of?(TacacsPlus::TacacsBody))
            entry_num = entry_num + 1
        end

        # open a socket to the server and send first packet
        socket = open_socket()
        packet = script.shift
        @dump_file.print("# Sent\n" + packet.to_yaml + "\n") if (@dump_file)
        pkt = TacacsPlus.encode_packet(packet,@key)
        socket.write(pkt)

        # process response
        while (!socket.closed?)
            # get packet from server.
            begin
                recvd_pkt = get_packet(socket,@key)
                if (!recvd_pkt)
                    @logger.debug("type=TacacsPlus , message=No response from server. Terminating connection.") if @logger
                    break
                end
            rescue Exception => error
                @logger.debug("Error with connection to server: #{error}") if @logger
                break
            end

            # send next packet if one exists
            if (script.length != 0)
                packet = script.shift
                @dump_file.print("# Sent\n" + packet.to_yaml + "\n") if (@dump_file)
                pkt = TacacsPlus.encode_packet(packet,@key)
                socket.write(pkt)
            else
                break
            end
         end

        socket.close if (!socket.closed?)
        return(nil)
    end

#==============================================================================#
# server_alive?()
#==============================================================================#

#===Synopsis
#Test a server to make sure that it is actively serving TACACS+ requests.
#The tests consists of an authentication request followed by an immediate abort.
#A valid user account is *not* needed in order to use this method.
#
#===Returns
# *true or false
#
    def server_alive?()
        alive = false

        # open a socket to the server
        begin
            socket = open_socket()
        rescue Exception
            return(alive)
        end

        # make start packet
        header = TacacsPlus::TacacsHeader.new
        if (@session_id)
            header.session_id = @session_id
        else
            header.randomize_session_id!
        end
        body = TacacsPlus::AuthenticationStart.new
        body.action_login!
        body.authen_type_ascii!
        body.priv_lvl = 1

        # send packet
        if (!socket.closed?)
            recvd_pkt = nil
            begin
                send_packet(socket,PacketStruct.new(header,body),@key)
                recvd_pkt = get_packet(socket,@key)
            rescue Exception => error
                @logger.debug("Error with connection to server: #{error}") if @logger
                return(alive)
            end

            if (recvd_pkt && recvd_pkt.body.kind_of?(AuthenticationReply) )
                # send abort
                body = TacacsPlus::AuthenticationContinue.new
                body.flag_abort!
                recvd_pkt.body = body
                recvd_pkt.header.inc_seq_no!
                send_packet(socket,recvd_pkt,@key)
                alive = true
            end
        end

        socket.close if (!socket.closed?)
        return(alive)
    end



# PRIVATE INSTANT METHODS
private

#==============================================================================#
# open_socket()
#==============================================================================#

# open socket to server
#
    def open_socket()
        socket = nil
        if @socket
            socket = @socket
        else
            Timeout::timeout(@sock_timeout) { socket = TCPSocket.new(@server, @port) }
            BasicSocket.do_not_reverse_lookup = true
        end

        return(socket)
    end

#==============================================================================#
# process_accounting()
#==============================================================================#

# main handler for accounting
#
    def process_accounting(session)

        if (session.reply.body.status_success?)
            session.pass_fail[:pass] = true
        end

        session.pass_fail[:server_msg] = session.reply.body.server_msg
        session.pass_fail[:data] = session.reply.body.data
        session.terminate = true
        return(nil)
    end

#==============================================================================#
# process_authentication()
#==============================================================================#

# main handler for authentication
#
    def process_authentication(session)
        authen_reply = session.reply

        if (authen_reply.header.seq_no >= 254)
            # seq_no wrapped. start over.
            msg = "Sequence Number reached 255. Sending 'abort' message to server."
            @logger.error(msg) if @logger
            body = TacacsPlus::AuthenticationContinue.new
            body.flag_abort!
            body.data = msg
            session.terminate = true
        elsif (authen_reply.body.status_getpass?)
            body = TacacsPlus::AuthenticationContinue.new
            body.user_msg = session.getpass
        elsif (authen_reply.body.status_pass?)
            session.pass_fail[:pass] = true
            session.terminate = true
        elsif(authen_reply.body.status_getuser?)
            body = TacacsPlus::AuthenticationContinue.new
            body.user_msg = session.getuser
        elsif(authen_reply.body.status_getdata?)
            body = TacacsPlus::AuthenticationContinue.new
            body.user_msg = session.getdata
        else
            session.pass_fail[:data] = authen_reply.body.data if (authen_reply.body.data_len != 0)
            session.pass_fail[:server_msg] = authen_reply.body.server_msg if (authen_reply.body.server_msg_len != 0)
            session.terminate = true
        end

        if (body)
            header = authen_reply.header.dup
            header.inc_seq_no!
            session.request = PacketStruct.new(header,body)
            session.expected_seq_no = session.expected_seq_no + 2
        end

        return(nil)
    end

#==============================================================================#
# process_authorization()
#==============================================================================#

# main handler for authorization
#
    def process_authorization(session)
        args = session.args

        if (session.reply.body.status_passadd?)
            args = session.reply.body.args
            session.pass_fail[:pass] = true
            session.pass_fail[:pass_type] = :add
        elsif (session.reply.body.status_passrepl?)
            args = session.reply.body.args
            session.pass_fail[:pass] = true
            session.pass_fail[:pass_type] = :repl
        end

        session.pass_fail[:server_msg] = session.reply.body.server_msg
        session.pass_fail[:data] = session.reply.body.data
        session.pass_fail[:args] = args
        session.terminate = true
        return(nil)
    end


#==============================================================================#
# process_response()
#==============================================================================#

# main handler for client/server communications
#
    def process_response(session,in_sock,out_sock=nil)
        session.expected_seq_no = 2
        session.pass_fail = {:data => '', :pass => false, :pass_type => nil, :server_msg => ''}

        # send first packet to server
        if (!out_sock)
            send_packet(in_sock,session.request,@key)
        else
            send_packet(out_sock,session.request,@key)
        end
        session.request = nil

        # process response
        while (!in_sock.closed?)
            # get packet from server.
            begin
                recvd_pkt = get_packet(in_sock,@key)
            rescue Exception => error
                @logger.debug("Error with connection to server: #{error}") if @logger
                break
            end

            # make sure encryption is used, unless testing. terminate if not
            if (recvd_pkt.header.flag_unencrypted?)
                if (!@testing)
                    @logger.error("Received unencrypted packet from server. Terminating connection.") if @logger
                    break
                end
            end

            # make sure seq_no is what we expected
            if (recvd_pkt.header.seq_no != session.expected_seq_no)
                @logger.error("Expected packet with seq_no #{session.expected_seq_no}, but was #{authen_reply.header.seq_no}.") if @logger
                break
            end

            # store recvd_pkt
            session.reply = recvd_pkt

            # authentication requests
            if (session.reply.header.type_authentication?)
                if (session.type != :authentication)
                    @logger.error("Received authentication message from server when client did not request authentication. " +
                                  "Terminating connection.") if (@logger)
                    break
                end

                if (session.reply.body.kind_of?(AuthenticationReply))
                    process_authentication(session)
                else
                    @logger.error("Expected AuthenticationReply from server, but #{session.reply.body.class} received. " +
                                  "Terminating connection.") if (@logger)
                    break
                end

            elsif (session.reply.header.type_authorization?)
                if (session.type != :authorization)
                    @logger.error("Received authorization message from server when client did not request authorization. " +
                                  "Terminating connection.") if (@logger)
                    break
                end

                if (session.reply.body.kind_of?(AuthorizationResponse))
                    process_authorization(session)
                else
                    @logger.error("Expected AuthorizationResponse from server, but #{session.reply.body.class} received. " +
                                  "Terminating connection.") if (@logger)
                    break
                end

            elsif (session.reply.header.type_accounting?)
                if (session.type != :accounting)
                    @logger.error("Received accounting message from server when client did not request accounting. " +
                                  "Terminating connection.") if (@logger)
                    break
                end

                if (session.reply.body.kind_of?(AccountingReply))
                    process_accounting(session)
                else
                    @logger.error("Expected AccountingReply from server, but #{session.reply.body.class} received. " +
                                  "Terminating connection.") if (@logger)
                    break
                end

            else
                @logger.error("Unknown value for header 'type' field: #{session.reply.header.type}. " +
                              "Terminating connection.") if (@logger)
                break
            end

            # send request to server
            if (session.request)
                if (!out_sock)
                    send_packet(in_sock,session.request,@key)
                else
                    send_packet(out_sock,session.request,@key)
                end
                session.request = nil
            end

            # close connection if finished
            break if session.terminate
         end

        in_sock.close if (!in_sock.closed?)
        return(session.pass_fail)
    end

#==============================================================================#
# Structures
#==============================================================================#

# used for aaa messages
    ClientSession = Struct.new(:request, :reply, :expected_seq_no, :pass_fail, :pass_type, :terminate, :type,
                               :getuser, :getpass, :getdata, :args) #:nodoc:


end # class Client


end # module TacacsPlus

__END__
