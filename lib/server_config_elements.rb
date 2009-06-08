module TacacsPlus

class Acl #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :name

    def initialize(tacacs_daemon,name,entries)
        @name = name
        @entries = []

        if (!name.kind_of?(String))
            raise ArgumentError, "Expected String for name of ACL, but #{name.class} provided."
        end

        if (!entries.kind_of?(Array))
            raise ArgumentError, "Expected Array for entries of ACL '#{name}', but #{entries.class} provided."
        end

        entries.each do |entry|
            begin
                e = AclEntry.new(tacacs_daemon,entry)
                @entries.push(e)
            rescue Exception => error
                raise ArgumentError, "Entry #{@entries.length + 1} of ACL '#{name}' raised the following errors: #{error}"
            end
        end
    end

#==============================================================================#
# match
#==============================================================================#

# check a NetAddr::CIDR against this acl
#
# return Hash
# :permit => True/False
# :by => String
#
    def match(cidr)
        line = 1

        @entries.each do |entry|
            if (entry.match?(cidr))
                if (entry.permission == :permit)
                    permit =  true
                else
                    permit =  false
                end
                return({:permit => permit, :by => "(line #{line})"})
            end
            line += 1
        end

        return({:permit => false, :by => '(implicit deny)'})
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = []
        @entries.each {|e| cfg.push(e.configuration)}
        return(cfg)
    end

end


class AclEntry #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :permission

    def initialize(tacacs_daemon,options)
        @any = false
        @cidr = nil
        @permission = nil
        @ip = nil
        @wildcard_mask = nil
        @network_object_group = nil

        known_args = [:permission, :ip, :wildcard_mask, :network_object_group]
        raise ArgumentError, "Expected Hash, but #{options.class} provided."if (!options.kind_of?(Hash))
        TacacsPlus.validate_args(options.keys,known_args)

        if (options.has_key?(:permission))
            raise ArgumentError, "Expected String for :permission, but '#{options[:permission].class}' received."  if (!options[:permission].kind_of?(String))
            raise ArgumentError, "Expected 'permit' or 'deny' for :permission, but was '#{options[:permission]}'." if(options[:permission] != 'permit' && options[:permission] != 'deny')
            @permission = options[:permission].to_sym
        else
            raise ArgumentError, "Argument :permission is missing."
        end

        if (options.has_key?(:ip))
            if (options[:ip] != 'any')
                begin
                    NetAddr.validate_ip_addr(options[:ip])
                rescue Exception => error
                    raise ArgumentError, "Argument :ip raised the following errors: #{error}"
                end
                @ip = options[:ip]

                if (options.has_key?(:wildcard_mask))
                    begin
                        NetAddr.validate_ip_addr(options[:wildcard_mask])
                    rescue Exception => error
                        raise ArgumentError, "Argument :wildcard_mask raised the following errors: #{error}"
                    end
                    @wildcard_mask = options[:wildcard_mask]
                    @cidr = NetAddr::CIDR.create(@ip, :WildcardMask => [@wildcard_mask,true])
                else
                    @cidr = NetAddr::CIDR.create(@ip)
                end
            else
                @any = true
            end

        elsif (options.has_key?(:network_object_group))
            @network_object_group = tacacs_daemon.network_object_groups(options[:network_object_group])
            if (!@network_object_group)
                raise ArgumentError, "Unknown Network Object Group '#{options[:network_object_group]}' referenced."
            end
        else
            raise ArgumentError, "ACL entry must have one of the following arguements: :ip or :network_object_group."
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {:permission => @permission.to_s}
        if (@any)
            cfg[:ip] = 'any'
        elsif (@ip)
            cfg[:ip] = @ip
            cfg[:wildcard_mask] = @wildcard_mask if (@wildcard_mask)
        else
            cfg[:network_object_group] = @network_object_group.name
        end
        return(cfg)
    end

#==============================================================================#
# match?
#==============================================================================#

# match NetAddr::CIDR against this entry
# return True/False

#
    def match?(cidr)
        if (@any)
            return(true)
        elsif (@cidr)
            if ( @cidr.matches?(cidr) )
                return(true)
            end
        else
            if (@network_object_group.match?(cidr))
                return(true)
            end
        end
        return(false)
    end

end


class AuthorAVPair #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :name

    def initialize(tacacs_daemon,name,entries)
        @name = name
        @entries = []

        if (!name.kind_of?(String))
            raise ArgumentError, "Expected String for name of AuthorAVPair, but #{name.class} provided."
        end

        if (!entries.kind_of?(Array))
            raise ArgumentError, "Expected Array for entries of AuthorAVPair '#{name}', but #{entries.class} provided."
        end

        entries.each do |entry|
            begin
                e = AuthorAVPairEntry.new(tacacs_daemon,entry)
                @entries.push(e)
            rescue Exception => error
                raise ArgumentError, "Entry #{@entries.length + 1} of AuthorAVPair '#{name}' raised the following errors: #{error}"
            end
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = []
        @entries.each {|e| cfg.push(e.configuration)}
        return(cfg)
    end

#==============================================================================#
# matching_entry
#==============================================================================#

# find matching entry on service and NetAddr::CIDR
# return AVPairs of matching entry or nil

#
    def matching_entry(service,cidr)
        match = nil
        @entries.each do |entry|
            if ( entry.match?(service,cidr) )
                match = entry.avpairs
                break
            end
        end
        return(match)
    end

end


class AuthorAVPairEntry #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    def initialize(tacacs_daemon,options)
        @acl = nil
        @avpairs = nil
        @dynamic_avpairs = []
        @network_av = nil
        @service = nil
        @shell_command_av = nil

        known_args = [:acl, :avpairs, :network_av, :service, :shell_command_av]
        raise ArgumentError, "Expected Hash, but #{options.class} provided."if (!options.kind_of?(Hash))
        TacacsPlus.validate_args(options.keys,known_args)

        if (options.has_key?(:acl))
            @acl = tacacs_daemon.acls(options[:acl])
            if (!@acl)
                raise ArgumentError, "Unknown ACL '#{options[:acl]}' referenced."
            end
        end

        if (options.has_key?(:service))
            raise ArgumentError, "Expected String for :service, but #{options[:service].class} provided." if (!options[:service].kind_of?(String))
            @service = options[:service]

        else
            raise ArgumentError, "No Service specified."
        end

        if (options.has_key?(:network_av))
            raise ArgumentError, "Expected Hash for :network_av, but #{options[:network_av].class} provided." if (!options[:network_av].kind_of?(Hash))
            @network_av = NetworkAV.new(tacacs_daemon, options[:network_av])
            @dynamic_avpairs.push(@network_av.avpair)
        end

        if (options.has_key?(:shell_command_av))
            raise ArgumentError, "Expected Hash for :shell_command_av, but #{options[:shell_command_av].class} provided." if (!options[:shell_command_av].kind_of?(Hash))
            @shell_command_av = ShellCommandAV.new(tacacs_daemon, options[:shell_command_av])
            @dynamic_avpairs.push(@shell_command_av.avpair)
        end

        if (options.has_key?(:avpairs))
            raise ArgumentError, "Expected Array for :avpairs, but #{options[:avpairs].class} provided." if (!options[:avpairs].kind_of?(Array))

           @avpairs = []
           options[:avpairs].each do |avpair|
                begin
                    TacacsPlus.validate_avpair(avpair)
                rescue Exception => msg
                    raise ArgumentError, "Error on avpair '#{avpair}' : #{msg}"
                end

                @avpairs.push(avpair)
            end

        else
            raise ArgumentError, "No AVPairs specified." if (!@network_av && !@shell_command_av)
        end

    end

#==============================================================================#
# avpairs
#==============================================================================#

    def avpairs
        avp = []
        avp.concat(@avpairs) if (@avpairs)
        avp.concat(@dynamic_avpairs) if (@dynamic_avpairs)
        return(avp)
    end


#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {:service => @service}
        cfg[:acl] = @acl.name if (@acl)
        cfg[:avpairs] = @avpairs if (@avpairs)
        cfg[:network_av] = @network_av.configuration if (@network_av)
        cfg[:shell_command_av] = @shell_command_av.configuration if (@shell_command_av)
        return(cfg)
    end

#==============================================================================#
# match?
#==============================================================================#

# match service and NetAddr::CIDR against this entry
# return True/False

#
    def match?(service,cidr)
        if (@acl)
            return(true) if ( @service == service && @acl.match(cidr)[:permit] )

        else
            return(true) if ( @service == service )
        end
        return(false)
    end


end


class CommandAuthorizationProfile #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :name

    def initialize(tacacs_daemon,name,entries)
        @name = name
        @entries = []

        if (!name.kind_of?(String))
            raise ArgumentError, "Expected String for name of Command Authorization Profile, but #{name.class} provided."
        end

        if (!entries.kind_of?(Array))
            raise ArgumentError, "Expected Array for entries of Command Authorization Profile '#{name}', but #{entries.class} provided."
        end

        entries.each do |entry|
            begin
                e = CommandAuthorizationProfileEntry.new(tacacs_daemon,entry)
                @entries.push(e)
            rescue Exception => error
                raise ArgumentError, "Entry #{@entries.length + 1} of Command Authorization Profile '#{name}' raised the following errors: #{error}"
            end
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = []
        @entries.each {|e| cfg.push(e.configuration)}
        return(cfg)
    end

#==============================================================================#
# matching_entry
#==============================================================================#

# find matching entry on command
# return nil on no match or Hash
# :rule => String
# :permit => True/False
# :by => String

#
    def matching_entry(command,cidr)
        match = nil
        @entries.each do |entry|
            rule = entry.match?(command)
            if (rule)
                ret = {:rule => rule, :permit => true}
                if (entry.acl)
                    acl_match = entry.acl.match(cidr)
                    ret[:permit] = acl_match[:permit]
                    ret[:by] = "ACL '#{entry.acl.name}' #{acl_match[:by]}"
                else
                    ret[:permit] = true
                end
                return(ret)
            end
        end
        return(nil)
    end

end


class CommandAuthorizationProfileEntry #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :acl

    def initialize(tacacs_daemon,options)
        @acl = nil
        @command = nil
        @shell_command_object_group = nil

        known_args = [:acl, :command, :shell_command_object_group]
        raise ArgumentError, "Expected Hash, but #{options.class} provided."if (!options.kind_of?(Hash))
        TacacsPlus.validate_args(options.keys,known_args)

        if (options.has_key?(:acl))
            @acl = tacacs_daemon.acls(options[:acl])
            if (!@acl)
                raise ArgumentError, "Unknown ACL '#{options[:acl]}' referenced."
            end
        end

        if (options.has_key?(:command))
            raise ArgumentError, "Expected String for :command, but #{options[:command].class} received." if(!options[:command].kind_of?(String))
            @command = Regexp.new(options[:command])

        elsif(options.has_key?(:shell_command_object_group))
            @shell_command_object_group = tacacs_daemon.shell_command_object_groups(options[:shell_command_object_group])
            if (!@shell_command_object_group)
                raise ArgumentError, "Unknown Shell Command Object Group '#{options[:shell_command_object_group]}' referenced."
            end

        else
            raise ArgumentError, "Command Authorization Profile entry must have one of the following arguements: :command or :shell_command_object_group."
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {}
        if (@command)
            cfg[:command] = @command.source
        else
            cfg[:shell_command_object_group] = @shell_command_object_group.name
        end

        cfg[:acl] = @acl.name if (@acl)
        return(cfg)
    end

#==============================================================================#
# match?
#==============================================================================#

# match command against this entry
# return matching rule (as String) or nil

#
    def match?(command)
        if (@command && @command.match(command) )
            return(@command.inspect)
        elsif (@shell_command_object_group)
            return( @shell_command_object_group.match?(command) )
        end
        return(nil)
    end

end



class CommandAuthorizationWhitelistEntry #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    def initialize(tacacs_daemon,options)
        @acl = nil
        @command = nil
        @shell_command_object_group = nil

        known_args = [:acl, :command, :shell_command_object_group]
        raise ArgumentError, "Expected Hash, but #{options.class} provided."if (!options.kind_of?(Hash))
        TacacsPlus.validate_args(options.keys,known_args)

        if (options.has_key?(:acl))
            @acl = tacacs_daemon.acls(options[:acl])
            if (!@acl)
                raise ArgumentError, "Unknown ACL '#{options[:acl]}' referenced."
            end
        end

        if (options.has_key?(:command))
            raise ArgumentError, "Expected String for :command, but #{options[:command].class} received." if(!options[:command].kind_of?(String))
            @command = Regexp.new(options[:command])

        elsif(options.has_key?(:shell_command_object_group))
            @shell_command_object_group = tacacs_daemon.shell_command_object_groups(options[:shell_command_object_group])
            if (!@shell_command_object_group)
                raise ArgumentError, "Unknown Shell Command Object Group '#{options[:shell_command_object_group]}' referenced."
            end

        else
            raise ArgumentError, "Command Authorization Whitelist entry must have one of the following arguements: :command or :shell_command_object_group."
        end

    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {}
        cfg[:acl] = @acl.name if (@acl)

        if (@command)
            cfg[:command] = @command.source
        else
            cfg[:shell_command_object_group] = @shell_command_object_group.name
        end
        return(cfg)
    end

#==============================================================================#
# match?
#==============================================================================#

# match command against this entry
# return matching rule (as String) or nil

#
    def match?(cidr,command)
        permit = true

        if (@acl)
            permit = @acl.match(cidr)[:permit]
        end

        if (permit)
            if (@command && @command.match(command))
                return(@command.inspect)
            elsif (@shell_command_object_group)
                return( @shell_command_object_group.match?(command) )
            end
        end
        return(nil)
    end

end



class NetworkAV #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    def initialize(tacacs_daemon,options)
        @attribute = nil
        @delimiter = nil
        @value = nil
        @tacacs_daemon = tacacs_daemon

        known_args = [:attribute, :delimiter, :value]
        raise ArgumentError, "Expected Hash for :network_av, but #{options.class} provided."if (!options.kind_of?(Hash))
        TacacsPlus.validate_args(options.keys,known_args)

        if (options.has_key?(:attribute))
            raise ArgumentError, "Expected String for :attribute of :network_av, but '#{options[:attribute].class}' received."  if (!options[:attribute].kind_of?(String))
            raise ArgumentError, "Argument :attribute of :network_av (#{options[:attribute]}) should end with a '=' or '*'." if (options[:attribute] !~ /=$/ && options[:attribute] !~ /\*$/)
            @attribute = options[:attribute]
        else
            raise ArgumentError, "Argument :attribute of :network_av is missing."
        end

        if (options.has_key?(:delimiter))
            raise ArgumentError, "Expected String for :delimiter of :network_av, but '#{options[:delimiter].class}' received."  if (!options[:delimiter].kind_of?(String))
            @delimiter = options[:delimiter]
        else
            raise ArgumentError, "Argument :delimiter of :network_av is missing."
        end

        if (options.has_key?(:value))
            raise ArgumentError, "Expected Array for :value of :network_av, but '#{options[:value].class}' received."  if (!options[:value].kind_of?(Array))

            options[:value].each do |x|
                if (!@tacacs_daemon.network_object_groups(x))
                    raise ArgumentError, "Unknown Network Object Group '#{x}' referenced by :network_av."
                end
            end
            @value = options[:value]
        else
            raise ArgumentError, "Argument :value of :network_av is missing."
        end
    end

#==============================================================================#
# avpair
#==============================================================================#

    def avpair
        avp = @attribute.dup
        cidrs = []
        @value.each do |x|
            @tacacs_daemon.network_object_groups(x).entries.each do |e|
                cidrs.push(e.to_s)
            end
        end
        avp << cidrs.join(@delimiter)

        return(avp)
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {:attribute => @attribute, :delimiter => @delimiter, :value => @value}
        return(cfg)
    end

end



class NetworkObjectGroup #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :name, :entries

    def initialize(name,entries)
        @name = name
        @entries = []

        if (!name.kind_of?(String))
            raise ArgumentError, "Expected String for name of Network Object Group, but #{name.class} provided."
        end

        if (!entries.kind_of?(Array))
            raise ArgumentError, "Expected Array for entries of Network Object Group '#{name}', but #{entries.class} provided."
        end

        entries.each do |entry|
            begin
                raise ArgumentError, "Expected String, but #{entry.class} received." if(!entry.kind_of?(String))
                @entries.push( NetAddr::CIDR.create(entry) )
            rescue Exception => error
                raise ArgumentError, "Entry #{@entries.length + 1} of Network Object Group '#{name}' raised the following errors: #{error}"
            end
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = []
        @entries.each {|e| cfg.push(e.desc)}
        return(cfg)
    end

#==============================================================================#
# match?
#==============================================================================#

# match NetAddr::CIDR against this group
# return True/False

#
    def match?(cidr)
        @entries.each do |entry|
            if ( entry.matches?(cidr) )
                return(true)
            end
        end
        return(false)
    end

end


class ShellCommandAV #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    def initialize(tacacs_daemon,options)
        @attribute = nil
        @delimiter = nil
        @value = nil
        @tacacs_daemon = tacacs_daemon

        known_args = [:attribute, :delimiter, :value]
        raise ArgumentError, "Expected Hash for :shell_command_av, but #{options.class} provided."if (!options.kind_of?(Hash))
        TacacsPlus.validate_args(options.keys,known_args)

        if (options.has_key?(:attribute))
            raise ArgumentError, "Expected String for :attribute of :shell_command_av, but '#{options[:attribute].class}' received."  if (!options[:attribute].kind_of?(String))
            raise ArgumentError, "Argument :attribute of :shell_command_av (#{options[:attribute]})should end with a '=' or '*'." if (options[:attribute] !~ /=$/ && options[:attribute] !~ /\*$/)
            @attribute = options[:attribute]
        else
            raise ArgumentError, "Argument :attribute of :shell_command_av is missing."
        end

        if (options.has_key?(:delimiter))
            raise ArgumentError, "Expected String for :delimiter of :shell_command_av, but '#{options[:delimiter].class}' received."  if (!options[:delimiter].kind_of?(String))
            @delimiter = options[:delimiter]
        else
            raise ArgumentError, "Argument :delimiter of :shell_command_av is missing."
        end

        if (options.has_key?(:value))
            raise ArgumentError, "Expected Array for :value of :shell_command_av, but '#{options[:value].class}' received."  if (!options[:value].kind_of?(Array))
            options[:value].each do |x|
                if (!@tacacs_daemon.shell_command_object_groups(x))
                    raise ArgumentError, "Unknown Shell Command Object Group '#{x}' referenced by :shell_command_av."
                end
            end
            @value = options[:value]
        else
            raise ArgumentError, "Argument :value of :shell_command_av is missing."
        end
    end

#==============================================================================#
# avpair
#==============================================================================#

    def avpair
        avp = @attribute.dup
        regexps = []
        @value.each do |x|
            @tacacs_daemon.shell_command_object_groups(x).entries.each do |e|
                regexps.push(e.source)
            end
        end
        avp << regexps.join(@delimiter)

        return(avp)
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {:attribute => @attribute, :delimiter => @delimiter, :value => @value}
        return(cfg)
    end

end



class ShellCommandObjectGroup #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :name, :entries

    def initialize(name,entries)
        @name = name
        @entries = []

        if (!name.kind_of?(String))
            raise ArgumentError, "Expected String for name of Shell Command Object Group, but #{name.class} provided."
        end

        if (!entries.kind_of?(Array))
            raise ArgumentError, "Expected Array for entries of Shell Command Object Group '#{name}', but #{entries.class} provided."
        end

        entries.each do |entry|
            begin
                raise ArgumentError, "Expected String, but #{entry.class} received." if(!entry.kind_of?(String))
                @entries.push( Regexp.new(entry) )
            rescue Exception => error
                raise ArgumentError, "Entry #{@entries.length + 1} of Shell Command Object Group '#{name}' raised the following errors: #{error}"
            end
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = []
        @entries.each {|e| cfg.push(e.source)}
        return(cfg)
    end

#==============================================================================#
# match?
#==============================================================================#

# match command against this entry
# return matching rule (as String) or nil

#
    def match?(command)
        @entries.each do |entry|
            if (entry.match(command))
                return(entry.inspect)
            end
        end
        return(nil)
    end


end



class TacacsDaemon #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :default_policy, :delimiter, :disabled_prompt, :ip, :key,
                :log_file, :log_accounting, :log_authentication, :log_authorization,
                :login_prompt, :name, :max_clients, :password_expired_prompt, :password_prompt,
                :port, :testing, :sock_timeout
    attr_accessor :command_authorization_whitelist, :dump_file, :logger, :logger_level

    def initialize(options)
        @default_policy = :deny
        @delimiter = "\t"
        @disabled_prompt = "Account has been disabled."
        @dump_file = nil
        @ip = '0.0.0.0'
        @key = nil
        @log_levels = {:debug => 0, :info => 1, :warn => 2, :error => 3, :fail => 4}
        @log_accounting = true
        @log_authentication = true
        @log_authorization = true
        @log_file = nil
        @logger = nil
        @logger_level = 2
        @login_prompt = "User Access Verification\n\nUsername: "
        @max_clients = 100
        @name = nil
        @password_expired_prompt = "Password has expired."
        @password_prompt = "Password: "
        @port = 49
        @testing = false
        @sock_timeout = 30

        # elements init
        @acls = {}
        @author_avpairs = {}
        @command_authorization_profiles = {}
        @network_object_groups = {}
        @shell_command_object_groups = {}
        @user_groups = {}
        @users = {}

        if (!options.kind_of?(Hash))
            raise ArgumentError, "Expected Hash, but #{options.class} provided."
        end

        known_args = [:default_policy, :disable_inactive, :disabled_prompt, :dump_file, :ip, :key, :log_accounting, :log_authentication,
                      :log_authorization, :logger, :log_level, :login_prompt, :name, :max_clients, :password_expired_prompt, :password_prompt,
                      :port, :sock_timeout, :testing, :delimiter]
        TacacsPlus.validate_args(options.keys,known_args)


        if (options.has_key?(:default_policy))
            raise ArgumentError, "Expected String for :default_policy, but '#{options[:default_policy].class}' " +
                                         "received."  if (!options[:default_policy].kind_of?(String))
            raise ArgumentError, "Expected  'permit' or 'deny' for :default_policy, but " +
                                 "was '#{options[:default_policy]}'." if(options[:default_policy] != 'permit' && options[:default_policy] != 'deny')
            @default_policy = options[:default_policy].to_sym
        end

        if (options.has_key?(:disabled_prompt))
            raise ArgumentError, "Expected String for :disabled_prompt, but #{options[:disabled_prompt].class} received." if(!options[:disabled_prompt].kind_of?(String))
            raise ArgumentError, "Custom disabled prompt must be less than 255 characters." if (options[:disabled_prompt].length > 255)
            @disabled_prompt = options[:disabled_prompt]
        end

        if (options.has_key?(:dump_file))
            if (options[:dump_file].kind_of?(IO) || options[:dump_file].kind_of?(String))
                @dump_file = options[:dump_file]
            else
                raise ArgumentError, "Expected IO or String for argument :dump_file, but #{options[:dump_file].class} provided."
            end
        end

        if (options.has_key?(:ip))
            begin
                NetAddr.validate_ip_addr(options[:ip])
            rescue Exception => error
                raise ArgumentError, "Argument :ip raised the following errors: #{error}"
            end
            @ip = options[:ip]
        end

        if (options.has_key?(:log_accounting))
            if (!options[:log_accounting].kind_of?(FalseClass) && !options[:log_accounting].kind_of?(TrueClass) )
                raise ArgumentError, "Expected True or False for argument :log_accounting, but #{options[:log_accounting].class} provided."
            end
            @log_accounting = options[:log_accounting]
        end

        if (options.has_key?(:log_authentication))
            if (!options[:log_authentication].kind_of?(FalseClass) && !options[:log_authentication].kind_of?(TrueClass) )
                raise ArgumentError, "Expected True or False for argument :log_authentication, but #{options[:log_authentication].class} provided."
            end
            @log_authentication = options[:log_authentication]
        end

        if (options.has_key?(:log_authorization))
            if (!options[:log_authorization].kind_of?(FalseClass) && !options[:log_authorization].kind_of?(TrueClass) )
                raise ArgumentError, "Expected True or False for argument :log_authorization, but #{options[:log_authorization].class} provided."
            end
            @log_authorization = options[:log_authorization]
        end

        if (options.has_key?(:logger))
            if ( options[:logger].kind_of?(String) )
                @log_file = options[:logger]
            else
                @logger = options[:logger]
            end
        else
            @logger = Logger.new(STDOUT)
        end

        if (options.has_key?(:log_level))
            if ( options[:log_level].kind_of?(Integer) )
                if ( (0..4).member?(options[:log_level]) )
                    @logger_level = options[:log_level]
                else
                    raise ArgumentError, "Argument :log_level should be between 0 and 4, but was #{options[:log_level]}."
                end
            else
                raise ArgumentError, "Expected Integer for argument :log_level, but #{options[:log_level].class} provided."
            end
        end

        if (options.has_key?(:login_prompt))
            raise ArgumentError, "Expected String for :login_prompt, but #{options[:login_prompt].class} received." if(!options[:login_prompt].kind_of?(String))
            raise ArgumentError, "Custom login prompt must be less than 255 characters." if (options[:login_prompt].length > 255)
            @login_prompt = options[:login_prompt]
        end

        if (options.has_key?(:max_clients))
            raise ArgumentError, "Expected Integer for :max_clients, but #{options[:max_clients].class} received." if(!options[:max_clients].kind_of?(Integer))
            @max_clients = options[:max_clients]
        end

        if (options.has_key?(:password_expired_prompt))
            raise ArgumentError, "Expected String for :password_expired_prompt, but #{options[:password_expired_prompt].class} received." if(!options[:password_expired_prompt].kind_of?(String))
            raise ArgumentError, "Custom password expired prompt must be less than 255 characters." if (options[:password_expired_prompt].length > 255)
            @password_expired_prompt = options[:password_expired_prompt]
        end

        if (options.has_key?(:password_prompt))
            raise ArgumentError, "Expected String for :password_prompt, but #{options[:password_prompt].class} received." if(!options[:password_prompt].kind_of?(String))
            raise ArgumentError, "Custom password prompt must be less than 255 characters." if (options[:password_prompt].length > 255)
            @password_prompt = options[:password_prompt]
        end

        if (options.has_key?(:port))
            raise ArgumentError, "Expected Integer for :port, but #{options[:port].class} received." if(!options[:port].kind_of?(Integer))
            if (options[:port] >= 2**16)
                raise ArgumentError, "#{options[:port]} is not a valid TCP port."
            end
            @port = options[:port]
        end

        if (options.has_key?(:sock_timeout))
            raise ArgumentError, "Expected Integer for :sock_timeout, but #{options[:sock_timeout].class} received." if(!options[:sock_timeout].kind_of?(Integer))
            @sock_timeout = options[:sock_timeout]
        end

        if (options.has_key?(:testing))
            if (!options[:testing].kind_of?(TrueClass) && !options[:testing].kind_of?(FalseClass) )
                raise ArgumentError, "Expected True or False for argument :testing, but #{options[:testing].class} provided."
            end
            @testing = options[:testing]
        end

        if (options.has_key?(:key))
            raise ArgumentError, "Expected String for :key, but #{options[:key].class} received." if(!options[:key].kind_of?(String))
            @key = options[:key]
        else
            raise ArgumentError, "Encryption key must be provied as part of :tacacs_daemon when not in testing mode." if (!@testing)
        end

        if (options.has_key?(:delimiter))
            if (!options[:delimiter].kind_of?(String))
                raise ArgumentError, "Expected String for :delimiter, but #{options[:delimiter].class} provided."
            end
            @delimiter = options[:delimiter]
        end

        if (options.has_key?(:name))
            if (!options[:name].kind_of?(String))
                raise ArgumentError, "Expected String for :name, but #{options[:name].class} provided."
            end
            @name = options[:name]
        end
    end

#==============================================================================#
# acls
#==============================================================================#

    def acls(name=nil)
        if (name)
            if ( @acls.has_key?(name) )
                return(@acls[name])
            else
                return(nil)
            end
        else
            return(@acls.values)
        end
    end

#==============================================================================#
# acls=
#==============================================================================#

    def acls=(list)
        @acls = {}
        list.each {|x| @acls[x.name] = x }
    end

#==============================================================================#
# author_avpairs
#==============================================================================#

    def author_avpairs(name=nil)
        if (name)
            if ( @author_avpairs.has_key?(name) )
                return(@author_avpairs[name])
            else
                return(nil)
            end
        else
            return(@author_avpairs.values)
        end
    end

#==============================================================================#
# author_avpairs=
#==============================================================================#

    def author_avpairs=(list)
        @author_avpairs = {}
        list.each {|x| @author_avpairs[x.name] = x }
    end

#==============================================================================#
# command_authorization_profiles
#==============================================================================#

    def command_authorization_profiles(name=nil)
        if (name)
            if ( @command_authorization_profiles.has_key?(name) )
                return(@command_authorization_profiles[name])
            else
                return(nil)
            end
        else
            return(@command_authorization_profiles.values)
        end
    end

#==============================================================================#
# command_authorization_profiles=
#==============================================================================#

    def command_authorization_profiles=(list)
        @command_authorization_profiles = {}
        list.each {|x| @command_authorization_profiles[x.name] = x }
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {:default_policy => @default_policy.to_s, :disabled_prompt => @disabled_prompt, :delimiter => @delimiter, :ip => @ip,
               :log_accounting => @log_accounting, :log_authentication => @log_authentication, :log_authorization => @log_authorization,
               :log_level => @logger_level, :login_prompt => @login_prompt, :max_clients => @max_clients, :password_expired_prompt => @password_expired_prompt,
               :password_prompt => @password_prompt, :port => @port, :sock_timeout => @sock_timeout, :testing => @testing }
        cfg[:dump_file] = @dump_file if (@dump_file)
        cfg[:key] = @key if (@key)
        cfg[:logger] = @logger if (@logger)
        cfg[:name] = @name if (@name)
        return(cfg)
    end

#==============================================================================#
# log()
#==============================================================================#

# log to @logger
#
    def log(level,fields,pkt=nil,peeraddr=nil,username=nil)
        return(nil) if (!@logger || @log_levels[level] < @logger_level)
        write_log = true
        fields.push("tacacs_daemon=#{@name}") if (@name)
        fields.push("client=#{peeraddr.ip}") if (peeraddr)

        if (pkt)
            if ( pkt.body.kind_of?(AuthorizationRequest) )
                if (@log_authorization)
                    username = pkt.body.user if (!username)
                    fields.concat( ["authen_method=#{pkt.body.xlate_authen_method}", "authen_type=#{pkt.body.xlate_authen_type}",
                                    "port=#{pkt.body.port}", "priv_lvl=#{pkt.body.priv_lvl.to_s}",
                                    "rem_addr=#{pkt.body.rem_addr}", "service=#{pkt.body.xlate_service}", "user=#{username}"] )
                else
                    write_log = false
                end

            elsif ( pkt.body.kind_of?(AccountingRequest) )
                if (@log_accounting)
                    username = pkt.body.user if (!username)
                    fields.concat( ["authen_method=#{pkt.body.xlate_authen_method}", "authen_type=#{pkt.body.xlate_authen_type}",
                                    "port=#{pkt.body.port}", "priv_lvl=#{pkt.body.priv_lvl.to_s}",
                                    "rem_addr=#{pkt.body.rem_addr}", "service=#{pkt.body.xlate_service}", "user=#{username}"] )
                else
                    write_log = false
                end

            elsif ( pkt.body.kind_of?(AuthenticationStart) )
                if (@log_authentication)
                    username = pkt.body.user if (!username)
                    fields.concat( ["action=#{pkt.body.xlate_action}", "authen_type=#{pkt.body.xlate_authen_type}",
                                    "port=#{pkt.body.port}", "priv_lvl=#{pkt.body.priv_lvl.to_s}",
                                    "rem_addr=#{pkt.body.rem_addr}", "service=#{pkt.body.xlate_service}","user=#{username}"] )
                else
                    write_log = false
                end
            end
        end

        if (write_log)
            fields = fields.join(@delimiter)
            fields.gsub!(/[\x00-\x08\x0a-\x1f\x7f-\xff]/, '.') # get rid of non-print characters

            if (level == :fatal)
                @logger.fatal(fields)
            elsif (level == :error)
                @logger.error(fields)
            elsif (level == :warn)
                @logger.warn(fields)
            elsif (level == :info)
                @logger.info(fields)
            else
                @logger.debug(fields)
            end
        end

        return(nil)
    end


#==============================================================================#
# network_object_groups
#==============================================================================#

    def network_object_groups(name=nil)
        if (name)
            if ( @network_object_groups.has_key?(name) )
                return(@network_object_groups[name])
            else
                return(nil)
            end
        else
            return(@network_object_groups.values)
        end
    end

#==============================================================================#
# network_object_groups=
#==============================================================================#

    def network_object_groups=(list)
        @network_object_groups = {}
        list.each {|x| @network_object_groups[x.name] = x }
    end

#==============================================================================#
# shell_command_object_groups
#==============================================================================#

    def shell_command_object_groups(name=nil)
        if (name)
            if ( @shell_command_object_groups.has_key?(name) )
                return(@shell_command_object_groups[name])
            else
                return(nil)
            end
        else
            return(@shell_command_object_groups.values)
        end
    end

#==============================================================================#
# shell_command_object_groups=
#==============================================================================#

    def shell_command_object_groups=(list)
        @shell_command_object_groups = {}
        list.each {|x| @shell_command_object_groups[x.name] = x }
    end

#==============================================================================#
# user_groups
#==============================================================================#

    def user_groups(name=nil)
        if (name)
            if ( @user_groups.has_key?(name) )
                return(@user_groups[name])
            else
                return(nil)
            end
        else
            return(@user_groups.values)
        end
    end

#==============================================================================#
# user_groups=
#==============================================================================#

    def user_groups=(list)
        @user_groups = {}
        list.each {|x| @user_groups[x.name] = x }
    end

#==============================================================================#
# users
#==============================================================================#

    def users(username=nil)
        if (username)
            if ( @users.has_key?(username) )
                return(@users[username])
            else
                return(nil)
            end
        else
            return(@users.values)
        end
    end

#==============================================================================#
# users=
#==============================================================================#

    def users=(list)
        @users = {}
        list.each {|x| @users[x.username] = x }
    end

end


class TacacsUser #:nodoc:

    attr_reader :username, :author_avpair, :command_authorization_profile, :disabled,
                :enable_acl, :login_acl, :user_group

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :author_avpair, :command_authorization_profile,
                :enable_password, :enable_acl, :login_acl, :login_password, :user_group

    def initialize(tacacs_daemon,username,options)
        @username = username
        @author_avpair = nil
        @command_authorization_profile = nil
        @disabled = false
        @enable_password = nil
        @enable_password_expires_on = nil
        @enable_password_lifespan = 0
        @enable_acl = nil
        @encryption = nil
        @login_acl = nil
        @login_password = nil
        @login_password_expires_on = nil
        @login_password_lifespan = 0
        @salt = nil
        @user_group = nil

        known_args = nil
        known_args = [:command_authorization_profile, :disabled, :enable_password, :enable_password_expires_on, :enable_password_lifespan,
                      :enable_acl, :encryption,:login_acl, :login_password, :login_password_expires_on, :login_password_lifespan,
                      :salt, :author_avpair, :user_group]

        if (!options.kind_of?(Hash))
            raise ArgumentError, "Expected Hash for options of User,  but #{options.class} provided."
        end

        if (!@username.kind_of?(String))
            raise ArgumentError, "Username should be a String, but was a #{@username.class}."
        end

        begin
            TacacsPlus.validate_args(options.keys,known_args)
        rescue Exception => error
            raise ArgumentError, "Error with user '#{@username}': #{error}"
        end

        if (options.has_key?(:author_avpair))
            raise ArgumentError, "Expected String for :author_avpair, but #{options[:author_avpair].class} " +
                                 "received for user '#{@username}'." if(!options[:author_avpair].kind_of?(String))
            @author_avpair = tacacs_daemon.author_avpairs(options[:author_avpair])
            if (!@author_avpair)
               raise ArgumentError, "Unknown AuthorAVPair '#{options[:author_avpair]}' received for user '#{@username}'."
            end
        end

        if (options.has_key?(:command_authorization_profile))
            raise ArgumentError, "Expected String for :command_authorization_profile, but #{options[:command_authorization_profile].class} " +
                                 "received for user '#{@username}'." if(!options[:command_authorization_profile].kind_of?(String))
            @command_authorization_profile = tacacs_daemon.command_authorization_profiles(options[:command_authorization_profile])
            if (!@command_authorization_profile)
               raise ArgumentError, "Unknown Command Authorization Profile '#{options[:command_authorization_profile]}' received for user '#{@username}'."
            end
        end

        if (options.has_key?(:enable_acl))
            raise ArgumentError, "Expected String for :enable_acl, but #{options[:enable_acl].class} " +
                                 "received for user '#{@username}'." if(!options[:enable_acl].kind_of?(String))
            @enable_acl = tacacs_daemon.acls(options[:enable_acl])
            if (!@enable_acl)
               raise ArgumentError, "Unknown enable ACL '#{options[:enable_acl]}' received for user '#{@username}'."
            end
        end

        if (options.has_key?(:login_acl))
            raise ArgumentError, "Expected String for :login_acl, but #{options[:login_acl].class} " +
                                 "received for user '#{@username}'." if(!options[:login_acl].kind_of?(String))
            @login_acl = tacacs_daemon.acls(options[:login_acl])
            if (!@login_acl)
               raise ArgumentError, "Unknown login ACL '#{options[:login_acl]}' received for user '#{@username}'."
            end
        end

        if (options.has_key?(:user_group))
            raise ArgumentError, "Expected String for :user_group, but #{options[:user_group].class} " +
                                 "received for user '#{@username}'." if(!options[:user_group].kind_of?(String))
            @user_group = tacacs_daemon.user_groups(options[:user_group])
            if (!@user_group)
               raise ArgumentError, "Unknown User Group '#{options[:user_group]}' received for user '#{@username}'."
            end
        end

        if (options.has_key?(:encryption))
            raise ArgumentError, "Expected String for :encryption, but #{options[:encryption].class} " +
                                 "received for user '#{@username}'." if(!options[:encryption].kind_of?(String))
            if (options[:encryption] != 'clear' && options[:encryption] != 'sha1')
                raise  ArgumentError, "Unrecognized value '#{options[:encryption]}' set for :encryption for user '#{@username}'. " +
                                      "Supported encryption schemes are 'clear' and 'sha1'."
            end
            @encryption = options[:encryption].to_sym
        end

        if (options.has_key?(:enable_password) && @encryption)
            raise ArgumentError, "Expected String for :enable_password, but #{options[:enable_password].class} " +
                                 "received for user '#{@username}'." if(!options[:enable_password].kind_of?(String))
            if (@encryption == :clear)
                raise  ArgumentError, "Enable password must be between 1 and 255 characters for user '#{@username}'." if (!(1..255).include?(options[:enable_password].length))
            elsif (@encryption == :sha1)
                raise  ArgumentError, "SHA1 hashed enable passwords must be exactly 40 characters for user '#{@username}'." if (options[:enable_password].length != 40)
            end
            @enable_password = options[:enable_password]
        elsif (options.has_key?(:enable_password) && !@encryption)
            raise ArgumentError, "Argument :enable_password provided, but no encryption specified for user '#{@username}'."
        end

        if (options.has_key?(:login_password) && @encryption)
            raise ArgumentError, "Expected String for :login_password, but #{options[:login_password].class} " +
                                 "received for user '#{@username}'." if(!options[:login_password].kind_of?(String))
            if (@encryption == :clear)
                raise  ArgumentError, "Login password must be between 1 and 255 characters for user '#{@username}'." if (!(1..255).include?(options[:login_password].length))
            elsif (@encryption == :sha1)
                raise  ArgumentError, "SHA1 hashed login passwords must be exactly 40 characters for user '#{@username}'." if (options[:login_password].length != 40)
            end
            @login_password = options[:login_password]
        elsif (options.has_key?(:login_password) && !@encryption)
            raise ArgumentError, "Argument :login_password provided, but no encryption specified for user '#{@username}'."
        end

        if (options.has_key?(:enable_password_lifespan))
            raise ArgumentError, "Expected Integer for :enable_password_lifespan, but #{options[:enable_password_lifespan].class} " +
                                 "received for user '#{@username}'." if(!options[:enable_password_lifespan].kind_of?(Integer))
            raise ArgumentError, "Argument :enable_password_lifespan must be 0 or greater for user '#{@username}'." if (options[:enable_password_lifespan] <  0)
            @enable_password_lifespan = options[:enable_password_lifespan]
        end

        if (options.has_key?(:login_password_lifespan))
            raise ArgumentError, "Expected Integer for :login_password_lifespan, but #{options[:login_password_lifespan].class} " +
                                 "received for user '#{@username}'." if(!options[:login_password_lifespan].kind_of?(Integer))
            raise ArgumentError, "Argument :password_lifespan must be 0 or greater for user '#{@username}'." if (options[:login_password_lifespan] <  0)
            @login_password_lifespan = options[:login_password_lifespan]
        end

        if (options.has_key?(:salt))
            raise ArgumentError, "Expected String for :salt, but #{options[:salt].class} " +
                                 "received for user '#{@username}'." if(!options[:salt].kind_of?(String))
            @salt = options[:salt]
        end

        if (options.has_key?(:disabled))
            if (!options[:disabled].kind_of?(TrueClass) && !options[:disabled].kind_of?(FalseClass) )
                raise ArgumentError, "Expected True or False for :disabled, but #{options[:disabled].class}  " +
                                     "received for user '#{@username}'."
            end
            @disabled= options[:disabled]
        end

        if (options.has_key?(:enable_password_expires_on))
            begin
                @enable_password_expires_on = Date.parse(options[:enable_password_expires_on])
            rescue
                raise ArgumentError, "Invalid date for :enable_password_expires_on for user '#{@username}'."
            end
        else
            @enable_password_expires_on = Date.today + @enable_password_lifespan
        end

        if (options.has_key?(:login_password_expires_on))
            begin
                @login_password_expires_on = Date.parse(options[:login_password_expires_on])
            rescue
                raise ArgumentError, "Invalid date for :login_password_expires_on for user '#{@username}'."
            end
        else
            @login_password_expires_on = Date.today + @login_password_lifespan
        end

    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {}
        cfg[:author_avpair] = @author_avpair.name if (@author_avpair)
        cfg[:command_authorization_profile] = @command_authorization_profile.name if (@command_authorization_profile)
        cfg[:disabled] = self.disabled? if (self.disabled?)
        cfg[:enable_password] = @enable_password if (@enable_password)
        cfg[:enable_password_expires_on] = @enable_password_expires_on.to_s if (@enable_password_expires_on)
        cfg[:enable_password_lifespan] = @enable_password_lifespan if (@enable_password_lifespan != 0)
        cfg[:enable_acl] = @enable_acl.name if (@enable_acl)
        cfg[:encryption] = @encryption.to_s if (@encryption)
        cfg[:login_acl] = @login_acl.name if (@login_acl)
        cfg[:login_password] = @login_password if (@login_password)
        cfg[:login_password_expires_on] = @login_password_expires_on.to_s if (@login_password_expires_on)
        cfg[:login_password_lifespan] = @login_password_lifespan if (@login_password_lifespan != 0)
        cfg[:salt] = @salt if (@salt)
        cfg[:user_group] = @user_group.name if (@user_group)
        return(cfg)
    end

#==============================================================================#
# disabled?
#==============================================================================#

    def disabled?
        return(@disabled)
    end

#==============================================================================#
# enable_password_expired?
#==============================================================================#

    def enable_password_expired?
        return(true) if (@enable_password_lifespan > 0 && @enable_password_expires_on <= Date.today)
        return(false)
    end

#==============================================================================#
# enable_password=
#==============================================================================#

    def enable_password=(pwd)
        if (@encryption == :sha1)
            @enable_password = encrypt_password(pwd)
        else
            @enable_password = pwd
        end

        if (@enable_password_lifespan != 0)
            @enable_password_expires_on = Date.today + @enable_password_lifespan
        end
    end

#==============================================================================#
# encrypt_password
#==============================================================================#
    def encrypt_password(pwd)
        return( Digest::SHA1.hexdigest(pwd + @salt) )
    end

#==============================================================================#
# login_password=
#==============================================================================#

    def login_password=(pwd)
        if (@encryption == :sha1)
            @login_password = encrypt_password(pwd)
        else
            @login_password = pwd
        end

        if (@login_password_lifespan != 0)
            @login_password_expires_on = Date.today + @login_password_lifespan
        end
    end

#==============================================================================#
# login_password_expired?
#==============================================================================#

    def login_password_expired?
        return(true) if (@login_password_lifespan > 0 && @login_password_expires_on <= Date.today)
        return(false)
    end

#==============================================================================#
# verify_enable_password
#==============================================================================#

    def verify_enable_password(pwd)
        pwd = encrypt_password(pwd) if (@encryption == :sha1)
        return(true) if (pwd == @enable_password)
        return(false)
    end

#==============================================================================#
# verify_login_password
#==============================================================================#

    def verify_login_password(pwd)
        pwd = encrypt_password(pwd) if (@encryption == :sha1)
        if (pwd == @login_password)
            return(true)
        end
        return(false)
    end

end


class UserGroup #:nodoc:

#==============================================================================#
# initialize
#==============================================================================#

    attr_reader :name, :author_avpair, :command_authorization_profile, :enable_acl, :login_acl

    def initialize(tacacs_daemon,name,options)
        @name = name
        @author_avpair = nil
        @command_authorization_profile = nil
        @enable_acl = nil
        @login_acl = nil

        known_args = nil
        known_args = [:author_avpair, :command_authorization_profile, :enable_acl, :login_acl]

        if (!options.kind_of?(Hash))
            raise ArgumentError, "Expected Hash for options of User,  but #{options.class} provided."
        end

        if (!@name.kind_of?(String))
            raise ArgumentError, "Name should be a String, but was a #{@name.class}."
        end

        begin
            TacacsPlus.validate_args(options.keys,known_args)
        rescue Exception => error
            raise ArgumentError, "Error with user '#{@name}': #{error}"
        end

        if (options.has_key?(:author_avpair))
            raise ArgumentError, "Expected String for :author_avpair, but #{options[:author_avpair].class} " +
                                 "received for User Group '#{@name}'." if(!options[:author_avpair].kind_of?(String))
            @author_avpair = tacacs_daemon.author_avpairs(options[:author_avpair])
            if (!@author_avpair)
               raise ArgumentError, "Unknown AuthorAVPair '#{options[:author_avpair]}' received for User Group '#{@name}'."
            end
        end

        if (options.has_key?(:command_authorization_profile))
            raise ArgumentError, "Expected String for :command_authorization_profile, but #{options[:command_authorization_profile].class} " +
                                 "received for User Group '#{@name}'." if(!options[:command_authorization_profile].kind_of?(String))
            @command_authorization_profile = tacacs_daemon.command_authorization_profiles(options[:command_authorization_profile])
            if (!@command_authorization_profile)
               raise ArgumentError, "Unknown Command Authorization Profile '#{options[:command_authorization_profile]}' received for User Group '#{@name}'."
            end
        end

        if (options.has_key?(:enable_acl))
            raise ArgumentError, "Expected String for :enable_acl, but #{options[:enable_acl].class} " +
                                 "received for User Group '#{@name}'." if(!options[:enable_acl].kind_of?(String))
            @enable_acl = tacacs_daemon.acls(options[:enable_acl])
            if (!@enable_acl)
               raise ArgumentError, "Unknown enable ACL '#{options[:enable_acl]}' received for User Group '#{@name}'."
            end
        end

        if (options.has_key?(:login_acl))
            raise ArgumentError, "Expected String for :login_acl, but #{options[:login_acl].class} " +
                                 "received for User Group '#{@name}'." if(!options[:login_acl].kind_of?(String))
            @login_acl = tacacs_daemon.acls(options[:login_acl])
            if (!@login_acl)
               raise ArgumentError, "Unknown login ACL '#{options[:login_acl]}' received for User Group '#{@name}'."
            end
        end
    end

#==============================================================================#
# configuration
#==============================================================================#

# config hash for this object
    def configuration
        cfg = {}
        cfg[:author_avpair] = @author_avpair.name if (@author_avpair)
        cfg[:command_authorization_profile] = @command_authorization_profile.name if (@command_authorization_profile)
        cfg[:enable_acl] = @enable_acl.name if (@enable_acl)
        cfg[:login_acl] = @login_acl.name if (@login_acl)
        return(cfg)
    end

end


end # module TacacsPlus