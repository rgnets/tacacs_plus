module TacacsPlus


class ClientConnection
private


#==============================================================================#
# process_accounting()
#==============================================================================#

# the main handler for accounting messages
#
    def process_accounting(session)
        acct_request = session.acct_request
        new_body = TacacsPlus::AccountingReply.new

        # fail if version unsupported
        if (acct_request.header.version != 0xc0)
                msg = "Client version of TACACS+ (0x#{acct_request.header.version.to_s(16)}) is unsupported."
                @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', "message=#{msg}"],acct_request,@peeraddr)
                acct_request.header.version = 0xc0
                new_body.status_error!
                new_body.server_msg = msg

        elsif (acct_request.body.args)
            # validate avpairs
            av_error = nil
            acct_request.body.args.each do |arg|
                begin
                    TacacsPlus.validate_avpair(arg)
                rescue => av_error
                    break
                end
            end

            if (!av_error)
                args = ['msg_type=Accounting', "message=Client provided the following args: #{acct_request.body.args.join(', ')}",
                        "status=Success", "flags=#{acct_request.body.xlate_flags}"]
                new_body.status_success!
                @tacacs_daemon.log(:warn,args,acct_request,@peeraddr)
            else
                msg = "AVPair provided by client raised the following error: #{av_error}"
                new_body.status_error!
                new_body.data = msg
                @tacacs_daemon.log(:debug,['msg_type=Accounting', "message=#{msg}", "status=Error"],acct_request,@peeraddr)
                end

        else
            msg = "Accounting request contained no args."
            new_body.status_error!
            new_body.data = msg
            @tacacs_daemon.log(:debug,['msg_type=Accounting', "message=#{msg}", "status=Error"],acct_request,@peeraddr)
        end

        # finish up
        session.reply.header = acct_request.header.dup
        session.reply.body = new_body
        session.terminate = true
        return(nil)
    end


end # class ClientConnection


end # module TacacsPlus

__END__
