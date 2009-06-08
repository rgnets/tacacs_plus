require File.join(File.dirname(__FILE__), 'client_connection_authentication.rb')
require File.join(File.dirname(__FILE__), 'client_connection_authorization.rb')
require File.join(File.dirname(__FILE__), 'client_connection_accounting.rb')

module TacacsPlus

class ClientConnection #:nodoc:

    attr_reader :socket, :peeraddr

# MIXINS
    include TacacsPlus::TacacsSocket


#==============================================================================#
# initialize
#==============================================================================#

    def initialize(tacacs_daemon,socket,peeraddr)
        @tacacs_daemon = tacacs_daemon
        @sock_timeout = @tacacs_daemon.sock_timeout # needed by TacacsSocket
        @dump_file = @tacacs_daemon.dump_file # needed by TacacsSocket
        @socket = socket
        @peeraddr = peeraddr
    end


#==============================================================================#
# process!
#==============================================================================#

#
    def process!
        sessions = {}

        while (!@socket.closed?)
            # get packet from client.
            begin
                recvd_pkt = get_packet(@socket,@tacacs_daemon.key)
                if (!recvd_pkt)
                    @tacacs_daemon.log(:debug,['msg_type=TacacsPlus::Server', 'message=No response from client. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end

            rescue Exception => error
                @tacacs_daemon.log(:debug,['msg_type=TacacsPlus::Server', "message=#{error} Terminating connection."],recvd_pkt,@peeraddr)
                break
            end

            # make sure encryption is used, unless testing. terminate if not
            if (recvd_pkt.header.flag_unencrypted?)
                if (!@tacacs_daemon.testing)
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received unencrypted packet from client. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end
            end

            session_id = recvd_pkt.header.session_id

            # if existing session. make sure expected_seq_no is correct and it is an authentication request
            if (sessions.has_key?(session_id))
                if (recvd_pkt.header.seq_no != sessions[session_id].expected_seq_no)
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received out of sequence packet from client. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end

                if (!recvd_pkt.header.type_authentication?)
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received non-authentication packet from client on non-initial request. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end

            # new session, make sure seq_no is 1
            else
                if (recvd_pkt.header.seq_no != 1)
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received out of sequence packet from client on initial request. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                else
                    if (recvd_pkt.header.type_authentication?)
                        sessions[session_id] = AuthenSession.new()
                    elsif (recvd_pkt.header.type_authorization?)
                        sessions[session_id] = AuthorSession.new()
                    elsif (recvd_pkt.header.type_accounting?)
                        sessions[session_id] = AcctSession.new()
                    else
                        sessions[session_id] = nil
                        @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', "message=Unknown value for header 'type' field: #{recvd_pkt.header.type}. Ignoring client."],recvd_pk,@peeraddr)
                    end
                end
            end


            session = sessions[session_id]

            # authentication requests
            if (session.kind_of?(AuthenSession))
                if (recvd_pkt.body.authentication_start?)
                    session.authen_start = recvd_pkt
                    session.expected_seq_no = 1
                    session.reply = PacketStruct.new
                    process_authentication(session)

                elsif (recvd_pkt.body.authentication_continue?)
                    session.authen_cont = recvd_pkt
                    process_authentication(session)

                else
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received Authentication Reply packet from client. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end

            # authorization requests
            elsif (session.kind_of?(AuthorSession))
                if (recvd_pkt.body.authorization_request?)
                    session.author_request = recvd_pkt
                    session.expected_seq_no = 1
                    session.reply = PacketStruct.new
                    process_authorization(session)
                else
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received Authorization Response packet from client. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end

            # accounting requests
            elsif (session.kind_of?(AcctSession))
                if (recvd_pkt.body.accounting_request?)
                    session.acct_request = recvd_pkt
                    session.expected_seq_no = 1
                    session.reply = PacketStruct.new
                    process_accounting(session)
                else
                    @tacacs_daemon.log(:error,['msg_type=TacacsPlus::Server', 'message=Received Authorization Reply packet from client. Terminating connection.'],recvd_pkt,@peeraddr)
                    break
                end
            end

            # if session still defined, then send reply to client. else delete session.
            if (session.reply)
                # send the reply and delete the session if terminate flag set
                session.reply.header.inc_seq_no!
                send_packet(@socket,session.reply.dup,@tacacs_daemon.key)
                sessions.delete(session_id) if (session.terminate)

            else
                sessions.delete(session_id)
            end

         end

        @socket.close if (!@socket.closed?)
        return(nil)
    end

#==============================================================================#
# Structures
#==============================================================================#

    AuthenSession = Struct.new(:authen_start, :authen_cont, :reply, :expected_seq_no,
                               :getuser, :getdata, :getpass, :terminate) #:nodoc:
    AuthorSession = Struct.new(:author_request, :reply, :expected_seq_no, :terminate) #:nodoc:
    AcctSession = Struct.new(:acct_request, :reply, :expected_seq_no, :terminate) #:nodoc:

end # ClientConnection

end # module TacacsPlus